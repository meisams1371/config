"""
X4G Ramzinex read-only egress relay.

Mounted by main.py at /egress. This service has no arbitrary-URL proxy:
it only forwards GET requests to explicitly allow-listed public Ramzinex
market-data endpoints.

Railway variables required:
  RAMZINEX_UPSTREAM_PROXY = http://2.179.95.57:8080
  RAMZINEX_RELAY_TOKEN    = a private random token, 32+ characters

Keep both values in Railway Variables, never in source control.
"""
from __future__ import annotations

import asyncio
import hmac
import logging
import os
import re
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Deque
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response

logger = logging.getLogger("X4G.ramzinex_relay")

app = FastAPI(
    title="X4G Ramzinex Read-only Relay",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

TOKEN = (
    os.environ.get("RAMZINEX_RELAY_TOKEN", "").strip()
    or os.environ.get("RADAR_RELAY_TOKEN", "").strip()
)
UPSTREAM_PROXY = os.environ.get("RAMZINEX_UPSTREAM_PROXY", "").strip()

BASE = "https://publicapi.ramzinex.com"
TIMEOUT = httpx.Timeout(connect=5.0, read=12.0, write=5.0, pool=5.0)
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
RATE_LIMIT_PER_MINUTE = 40
RATE_WINDOW_SECONDS = 60

_cache: dict | None = None
_cache_at = 0.0
_cache_lock = asyncio.Lock()
_rate_lock = asyncio.Lock()
_rate_buckets: dict[str, Deque[float]] = defaultdict(deque)

PAIR_ID = r"[1-9][0-9]{0,8}"
_ALLOWED_PATTERNS = (
    re.compile(r"^pairs$"),
    re.compile(rf"^pairs/{PAIR_ID}$"),
    re.compile(r"^orderbooks/buys_sells$"),
    re.compile(rf"^orderbooks/{PAIR_ID}/(?:buys_sells|buys|sells)$"),
    re.compile(rf"^orderbooks/{PAIR_ID}/market_(?:buy|sell)_price$"),
    re.compile(r"^currencies$"),
    re.compile(r"^networks$"),
    re.compile(r"^prices$"),
)

_QUERY_ALLOWLIST = {
    "networks": {"currency_id", "withdraw", "deposit"},
    "market_buy_price": {"amount2"},
    "market_sell_price": {"amount"},
}


def _proxy_is_valid() -> bool:
    if not UPSTREAM_PROXY:
        return False
    try:
        parsed = urlsplit(UPSTREAM_PROXY)
        return (
            parsed.scheme in ("http", "https")
            and bool(parsed.hostname)
            and parsed.port is not None
            and parsed.username is None
            and parsed.password is None
            and parsed.path in ("", "/")
            and not parsed.query
            and not parsed.fragment
        )
    except Exception:
        return False


def _require_config() -> None:
    if not TOKEN or len(TOKEN) < 32 or not _proxy_is_valid():
        raise HTTPException(status_code=503, detail="Ramzinex relay is not configured")


def _authorize(request: Request) -> None:
    supplied = request.headers.get("X-Relay-Token", "")
    if not supplied:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            supplied = auth[7:]
    if not TOKEN or not hmac.compare_digest(supplied, TOKEN):
        raise HTTPException(status_code=401, detail="Unauthorized")


def _allowed_path(path: str) -> bool:
    return any(pattern.fullmatch(path) for pattern in _ALLOWED_PATTERNS)


def _allowed_query_names(path: str) -> set[str]:
    if path == "networks":
        return _QUERY_ALLOWLIST["networks"]
    if path.endswith("/market_buy_price"):
        return _QUERY_ALLOWLIST["market_buy_price"]
    if path.endswith("/market_sell_price"):
        return _QUERY_ALLOWLIST["market_sell_price"]
    return set()


def _query_params(request: Request, path: str) -> dict[str, str]:
    allowed = _allowed_query_names(path)
    params: dict[str, str] = {}
    for key, value in request.query_params.multi_items():
        if key not in allowed:
            raise HTTPException(status_code=400, detail=f"Unsupported query parameter: {key}")
        if len(value) > 64 or key in params:
            raise HTTPException(status_code=400, detail="Invalid query parameter")
        params[key] = value
    return params


async def _rate_check(request: Request) -> None:
    ip = request.client.host if request.client else "unknown"
    now = time.monotonic()
    async with _rate_lock:
        bucket = _rate_buckets[ip]
        while bucket and now - bucket[0] > RATE_WINDOW_SECONDS:
            bucket.popleft()
        if len(bucket) >= RATE_LIMIT_PER_MINUTE:
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
        bucket.append(now)
        if len(_rate_buckets) > 2048:
            for key in list(_rate_buckets.keys())[:512]:
                old = _rate_buckets[key]
                while old and now - old[0] > RATE_WINDOW_SECONDS:
                    old.popleft()
                if not old:
                    _rate_buckets.pop(key, None)


def _upstream_path(path: str) -> str:
    if path == "prices":
        return "/exchange/api/exchange/prices"
    return f"/exchange/api/v1.0/exchange/{path}"


async def _fetch_upstream(path: str, params: dict[str, str] | None = None) -> tuple[int, bytes, dict[str, str]]:
    target = BASE + _upstream_path(path)
    async with httpx.AsyncClient(
        proxies=UPSTREAM_PROXY,
        timeout=TIMEOUT,
        follow_redirects=False,
        trust_env=False,
        limits=httpx.Limits(max_connections=8, max_keepalive_connections=4),
        headers={
            "User-Agent": "X4G-Ramzinex-ReadOnlyRelay/1.0",
            "Accept": "application/json",
        },
    ) as client:
        async with client.stream("GET", target, params=params or {}) as upstream:
            body = await upstream.aread()
            if len(body) > MAX_RESPONSE_BYTES:
                raise HTTPException(status_code=502, detail="Upstream response exceeded size limit")
            headers = {}
            for name in ("content-type", "cache-control", "etag", "last-modified"):
                value = upstream.headers.get(name)
                if value:
                    headers[name] = value
            return upstream.status_code, body, headers


def _json_summary(name: str, status: int, body: bytes) -> dict:
    try:
        payload = __import__("json").loads(body)
        valid = True
    except Exception:
        payload, valid = None, False

    items = None
    keys = None
    if isinstance(payload, list):
        items = len(payload)
    elif isinstance(payload, dict):
        keys = list(payload.keys())[:12]
        data = payload.get("data")
        if isinstance(data, list):
            items = len(data)
        elif isinstance(data, dict):
            items = len(data)

    return {
        "name": name,
        "http_status": status,
        "valid_json": valid,
        "items_or_data_keys": items if items is not None else (
            list(payload.get("data", {}).keys())[:12]
            if isinstance(payload, dict) and isinstance(payload.get("data"), dict)
            else None
        ),
        "top_level_keys": keys,
    }


@app.get("/health")
async def health() -> dict:
    return {
        "ok": True,
        "service": "x4g-ramzinex-readonly-relay",
        "upstream_proxy_configured": _proxy_is_valid(),
        "relay_token_configured": len(TOKEN) >= 32,
        "mode": "GET-only, allow-listed",
    }


@app.get("/ramzinex/{path:path}")
async def ramzinex_readonly(path: str, request: Request):
    _require_config()
    _authorize(request)
    normalized = path.strip("/")
    if not normalized or not _allowed_path(normalized):
        raise HTTPException(status_code=404, detail="Endpoint is not allow-listed")
    await _rate_check(request)
    params = _query_params(request, normalized)

    started = time.monotonic()
    try:
        status, body, headers = await _fetch_upstream(normalized, params)
        elapsed_ms = round((time.monotonic() - started) * 1000)
        logger.info(
            "Ramzinex GET path=%s status=%s elapsed_ms=%s bytes=%s",
            normalized, status, elapsed_ms, len(body)
        )
        return Response(content=body, status_code=status, headers=headers)
    except HTTPException:
        raise
    except httpx.TimeoutException:
        logger.warning("Ramzinex upstream timeout path=%s", normalized)
        raise HTTPException(status_code=504, detail="Ramzinex upstream timed out")
    except httpx.RequestError as exc:
        logger.warning("Ramzinex upstream connection error path=%s type=%s", normalized, type(exc).__name__)
        raise HTTPException(status_code=502, detail="Ramzinex upstream connection failed")
    except Exception as exc:
        logger.exception("Unexpected Ramzinex relay failure path=%s type=%s", normalized, type(exc).__name__)
        raise HTTPException(status_code=502, detail="Ramzinex relay failed")


@app.get("/radar/probe")
async def probe(request: Request):
    _require_config()
    _authorize(request)
    global _cache, _cache_at

    now = time.monotonic()
    if _cache is not None and now - _cache_at < 30:
        return {"cached": True, **_cache}

    async with _cache_lock:
        now = time.monotonic()
        if _cache is not None and now - _cache_at < 30:
            return {"cached": True, **_cache}

        await _rate_check(request)
        names_and_paths = (
            ("pairs", "pairs"),
            ("pair_2", "pairs/2"),
            ("orderbook_pair_2", "orderbooks/2/buys_sells"),
            ("all_orderbooks", "orderbooks/buys_sells"),
            ("prices", "prices"),
        )
        results = []
        for name, path in names_and_paths:
            try:
                status, body, _ = await _fetch_upstream(path)
                results.append(_json_summary(name, status, body))
            except httpx.TimeoutException:
                results.append({"name": name, "error": "Timeout"})
            except httpx.RequestError as exc:
                results.append({"name": name, "error": type(exc).__name__})
            except HTTPException as exc:
                results.append({"name": name, "error": exc.status_code})

        try:
            status, body, _ = await _fetch_upstream("currencies")
            results.append(_json_summary("currencies", status, body))
        except Exception as exc:
            results.append({"name": "currencies", "error": type(exc).__name__})

        try:
            async with httpx.AsyncClient(
                proxies=UPSTREAM_PROXY,
                timeout=TIMEOUT,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                response = await client.get("https://api.ipify.org?format=json")
                ip_data = response.json() if response.status_code == 200 else {}
                egress = {
                    "http_status": response.status_code,
                    "ip": ip_data.get("ip") if isinstance(ip_data, dict) else None,
                }
        except Exception as exc:
            egress = {"error": type(exc).__name__}

        _cache = {
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "egress": egress,
            "ramzinex": results,
        }
        _cache_at = time.monotonic()
        return {"cached": False, **_cache}


@app.get("/radar/orderbooks/{pair_id}")
async def orderbook(pair_id: int, request: Request):
    _require_config()
    _authorize(request)
    if pair_id < 1 or pair_id > 999999999:
        raise HTTPException(status_code=400, detail="invalid pair id")
    await _rate_check(request)
    path = f"orderbooks/{pair_id}/buys_sells"
    try:
        status, body, headers = await _fetch_upstream(path)
        return Response(content=body, status_code=status, headers=headers)
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Ramzinex upstream timed out")
    except httpx.RequestError:
        raise HTTPException(status_code=502, detail="Ramzinex upstream connection failed")


@app.get("/radar/egress")
async def egress(request: Request):
    _require_config()
    _authorize(request)
    await _rate_check(request)
    try:
        async with httpx.AsyncClient(
            proxies=UPSTREAM_PROXY,
            timeout=TIMEOUT,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            response = await client.get("https://api.ipify.org?format=json")
            return {"http_status": response.status_code, "body": response.json() if response.status_code == 200 else None}
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Egress IP lookup timed out")
    except httpx.RequestError:
        raise HTTPException(status_code=502, detail="Egress IP lookup failed")
