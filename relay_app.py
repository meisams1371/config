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
import html
import ipaddress
import json
import logging
import os
import re
import socket
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from typing import Deque
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, Response
from starlette.websockets import WebSocketState
import websockets

from vless_egress import manager as _vless_egress_manager

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
WS_ENDPOINT = "wss://websocket.ramzinex.ir/websocket"
WS_MAX_MESSAGE_BYTES = 64 * 1024
WS_MAX_CONNECTIONS_PER_IP = 3
WS_MAX_CONNECTIONS_TOTAL = 100
_PUBLIC_WS_CHANNEL = re.compile(r"^(?:orderbook|last-trades):[1-9][0-9]{0,8}$|^public:orderbook:[1-9][0-9]{0,8}$")
RATE_LIMIT_PER_MINUTE = 40
RATE_WINDOW_SECONDS = 60

_cache: dict | None = None
_cache_at = 0.0
_cache_lock = asyncio.Lock()
_rate_lock = asyncio.Lock()
_rate_buckets: dict[str, Deque[float]] = defaultdict(deque)
_ws_active_by_ip: dict[str, int] = defaultdict(int)
_ws_active_total = 0
_ws_active_lock = asyncio.Lock()

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
    # The proxy is selected and verified at runtime. Only the relay token is a
    # mandatory deployment secret; RAMZINEX_UPSTREAM_PROXY is an optional pin.
    if not TOKEN or len(TOKEN) < 32:
        raise HTTPException(status_code=503, detail="Ramzinex relay token is not configured")


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
    last_error: Exception | None = None

    # One full retry cycle is allowed after refreshing the route list. Requests
    # remain GET-only and can safely move to another verified public egress.
    for cycle in range(2):
        proxy_urls = await _get_ramzinex_proxy_urls(force_refresh=(cycle > 0))
        if not proxy_urls:
            break

        for proxy_url in proxy_urls:
            route_failed = False
            for attempt in range(2):
                try:
                    async with httpx.AsyncClient(
                        proxies=proxy_url,
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
                            if upstream.status_code in (403, 407, 429) or upstream.status_code >= 500:
                                last_error = httpx.ConnectError(
                                    f"Verified route returned upstream HTTP {upstream.status_code}"
                                )
                                route_failed = True
                                break
                            body = await upstream.aread()
                            if len(body) > MAX_RESPONSE_BYTES:
                                raise HTTPException(status_code=502, detail="Upstream response exceeded size limit")
                            headers = {}
                            for name in ("content-type", "cache-control", "etag", "last-modified"):
                                value = upstream.headers.get(name)
                                if value:
                                    headers[name] = value
                            return upstream.status_code, body, headers
                except HTTPException:
                    raise
                except httpx.RequestError as exc:
                    last_error = exc
                    if attempt == 0:
                        await asyncio.sleep(0.35)
                        continue
                    route_failed = True

            if route_failed:
                await _mark_ramzinex_proxy_failed(proxy_url)

    if last_error:
        raise last_error
    raise HTTPException(
        status_code=503,
        detail="No currently verified Iran egress route is available for Ramzinex",
    )


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


# ── Daily Iranian proxy discovery ────────────────────────────────────────────
# Selector's option 13 is an MTProto-only finder. Its public source contains
# Telegram proxy links; we separately check TCP reachability and resolve the
# endpoint IP's country. A TCP-open result is NOT called a confirmed Telegram
# handshake. For Ramzinex, only HTTP/HTTPS proxies that pass IP + GeoIP +
# read-only exchange API checks are reported as usable.
HTTP_PROXY_SOURCE = (
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/"
    "proxies/countries/IR/data.json"
)
# ProxySpace republishes country-specific HTTP and HTTPS proxy candidates every
# 20 minutes. Its lists are explicitly untested; every candidate still passes
# our own independent GeoIP, Ramzinex REST and Centrifuge WebSocket checks.
PROXYSPACE_IR_HTTP_SOURCE = "https://proxyspace.pro/country/ir/http.txt"
PROXYSPACE_IR_HTTPS_SOURCE = "https://proxyspace.pro/country/ir/https.txt"
MTPROTO_SOURCE = (
    "https://raw.githubusercontent.com/Kolandone/v2raycollector/main/proxy.txt"
)
VLESS_SOURCE = (
    "https://raw.githubusercontent.com/mmbateni/iran-intranet-access/main/outputs/iran_appearing.txt"
)
IP_ECHO_URL = "https://api.ipify.org?format=json"
RAMZINEX_PAIRS_URL = BASE + "/exchange/api/v1.0/exchange/pairs/2"
RAMZINEX_ORDERBOOK_URL = BASE + "/exchange/api/v1.0/exchange/orderbooks/2/buys_sells"
_scan_cache: dict | None = None
_scan_cache_at = 0.0
_scan_lock = asyncio.Lock()
_SCAN_TTL_SECONDS = 1800
_HTTP_SCAN_LIMIT = max(8, min(36, int(os.environ.get("IRAN_PROXY_SCAN_LIMIT", "36"))))
_MTPROTO_SCAN_LIMIT = max(8, min(36, int(os.environ.get("IRAN_MTPROTO_SCAN_LIMIT", "20"))))
_DIRECT_TIMEOUT = httpx.Timeout(connect=6.0, read=8.0, write=6.0, pool=4.0)


def _public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
        return address.is_global
    except Exception:
        return False


async def _geoip_votes(client: httpx.AsyncClient, ip: str) -> dict:
    """Two-of-three independent GeoIP votes. These requests go direct, not via proxy."""
    checks = {
        "ipwho": f"https://ipwho.is/{ip}",
        "ipapi": f"https://ipapi.co/{ip}/json/",
        "ip_api": f"http://ip-api.com/json/{ip}?fields=status,countryCode,city,isp,as",
    }

    async def one(name: str, url: str):
        try:
            response = await client.get(url, timeout=5.0)
            if response.status_code != 200:
                return name, None
            data = response.json()
            if name == "ipwho":
                if not data.get("success"):
                    return name, None
                country = data.get("country_code")
                city = data.get("city")
            elif name == "ipapi":
                country = data.get("country_code")
                city = data.get("city")
            else:
                if data.get("status") != "success":
                    return name, None
                country = data.get("countryCode")
                city = data.get("city")
            return name, {
                "country": str(country or "").upper(),
                "city": city,
            }
        except Exception:
            return name, None

    results = await asyncio.gather(*(one(k, v) for k, v in checks.items()))
    votes = {}
    for name, item in results:
        if item and item.get("country"):
            votes[name] = item
    iran_votes = sum(1 for item in votes.values() if item["country"] == "IR")
    return {
        "votes": votes,
        "iran_votes": iran_votes,
        "vote_count": len(votes),
        "iran_confirmed": iran_votes >= 2,
        "city": next(
            (item.get("city") for item in votes.values()
             if item.get("country") == "IR" and item.get("city")),
            None,
        ),
    }


def _http_proxy_candidates(payload: object) -> list[dict]:
    if not isinstance(payload, list):
        return []
    rows = []
    seen = set()
    for item in payload:
        if not isinstance(item, dict):
            continue
        proxy = str(item.get("proxy") or "").strip()
        try:
            parsed = urlsplit(proxy)
            if parsed.scheme not in ("http", "https"):
                continue
            if not parsed.hostname or not parsed.port:
                continue
            if parsed.username or parsed.password or parsed.query or parsed.fragment:
                continue
            ip = str(item.get("ip") or parsed.hostname)
            address = ipaddress.ip_address(ip)
            if not address.is_global:
                continue
            if parsed.hostname != ip:
                continue
            key = f"{parsed.scheme}://{ip}:{parsed.port}"
            if key in seen:
                continue
            seen.add(key)
            rows.append({
                "proxy": key,
                "ip": ip,
                "port": parsed.port,
                "scheme": parsed.scheme,
                "anonymity": str(item.get("anonymity") or "unknown"),
                "listed_city": str((item.get("geolocation") or {}).get("city") or "Unknown"),
                "score": int(item.get("score") or 0),
            })
        except Exception:
            continue

    # Re-test the endpoint that previously passed the Iran + Ramzinex checks first.
    rows.sort(key=lambda row: (
        row["ip"] != "2.179.95.57",
        row["anonymity"] != "elite",
        row["score"] * -1,
        row["listed_city"] == "Unknown",
    ))
    return rows[:_HTTP_SCAN_LIMIT]


def _proxyspace_candidates(http_text: str = "", https_text: str = "") -> list[dict]:
    """Parse ProxySpace Iran HTTP/HTTPS candidate lists (ip:port, not pre-verified)."""
    rows: list[dict] = []
    seen: set[str] = set()
    for protocol_label, content in (("http", http_text), ("https", https_text)):
        for raw in str(content or "").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or len(line) > 96:
                continue
            try:
                ip, port_text = line.rsplit(":", 1)
                address = ipaddress.ip_address(ip.strip())
                port = int(port_text.strip())
                if not address.is_global or not (1 <= port <= 65535):
                    continue
                # ProxySpace's examples use an HTTP proxy transport even for
                # its HTTPS-capable list; the label means HTTPS destination support.
                proxy_url = f"http://{address.compressed}:{port}"
                if proxy_url in seen:
                    continue
                seen.add(proxy_url)
                rows.append({
                    "proxy": proxy_url,
                    "ip": address.compressed,
                    "port": port,
                    "scheme": "http",
                    "anonymity": f"proxyspace-{protocol_label}",
                    "listed_city": "Iran-list-unverified",
                })
            except Exception:
                continue
    return rows


async def _test_http_proxy(candidate: dict, direct_client: httpx.AsyncClient) -> dict:
    proxy_url = candidate["proxy"]
    started = time.monotonic()
    result = {
        "proxy": proxy_url,
        "ip": candidate["ip"],
        "port": candidate["port"],
        "anonymity": candidate["anonymity"],
        "listed_city": candidate["listed_city"],
    }
    try:
        async with httpx.AsyncClient(
            proxies=proxy_url,
            timeout=_DIRECT_TIMEOUT,
            follow_redirects=False,
            trust_env=False,
            headers={
                "User-Agent": "X4G-Iran-Proxy-Audit/1.0",
                "Accept": "application/json",
            },
        ) as proxy_client:
            # The observed exit IP must be read through the candidate proxy.
            echo = await proxy_client.get(IP_ECHO_URL)
            if echo.status_code != 200:
                return {**result, "status": "ip_echo_failed", "http_status": echo.status_code}
            try:
                exit_ip = str(echo.json().get("ip") or "")
            except Exception:
                exit_ip = ""
            if not _public_ip(exit_ip):
                return {**result, "status": "invalid_exit_ip"}

            # GeoIP lookups are direct queries for the observed proxy exit IP.
            geo = await _geoip_votes(direct_client, exit_ip)
            result["exit_ip"] = exit_ip
            result["geoip"] = geo
            if not geo["iran_confirmed"]:
                return {
                    **result,
                    "status": "not_confirmed_iran",
                    "latency_ms": round((time.monotonic() - started) * 1000),
                }

            async def get_with_retry(url: str):
                last_error = None
                for attempt in range(3):
                    try:
                        response = await proxy_client.get(url)
                        return response, None
                    except httpx.RequestError as exc:
                        last_error = exc
                        if attempt < 2:
                            await asyncio.sleep(0.5 * (attempt + 1))
                return None, last_error

            pair_started = time.monotonic()
            pairs, pairs_error = await get_with_retry(RAMZINEX_PAIRS_URL)
            pair_ms = round((time.monotonic() - pair_started) * 1000)
            if pairs is None:
                raise pairs_error or httpx.ConnectError("pairs request failed")

            book_started = time.monotonic()
            book, book_error = await get_with_retry(RAMZINEX_ORDERBOOK_URL)
            book_ms = round((time.monotonic() - book_started) * 1000)
            if book is None:
                raise book_error or httpx.ConnectError("orderbook request failed")

            pair_json = False
            book_json = False
            try:
                pair_data = pairs.json()
                pair_json = isinstance(pair_data, (dict, list))
            except Exception:
                pass
            try:
                book_data = book.json()
                book_json = isinstance(book_data, (dict, list))
            except Exception:
                pass

            result.update({
                "pairs_status": pairs.status_code,
                "pairs_json": pair_json,
                "pairs_ms": pair_ms,
                "orderbook_status": book.status_code,
                "orderbook_json": book_json,
                "orderbook_ms": book_ms,
                "latency_ms": round((time.monotonic() - started) * 1000),
            })
            result["ramzinex_ready"] = (
                pairs.status_code == 200 and pair_json
                and book.status_code == 200 and book_json
            )
            result["status"] = "ramzinex_ready" if result["ramzinex_ready"] else "iran_exit_only"
            return result
    except Exception as exc:
        return {
            **result,
            "status": "connection_failed",
            "error": type(exc).__name__,
            "detail": str(exc)[:180],
            "latency_ms": round((time.monotonic() - started) * 1000),
        }


async def _test_ramzinex_websocket_proxy(proxy_url: str) -> bool:
    """Require a real WebSocket upgrade and Centrifuge connect/subscribe ACK."""
    try:
        async with websockets.connect(
            WS_ENDPOINT,
            proxy=proxy_url,
            subprotocols=["centrifuge-json"],
            open_timeout=14,
            close_timeout=3,
            ping_interval=None,
            max_size=WS_MAX_MESSAGE_BYTES,
            compression=None,
        ) as ws:
            if ws.subprotocol != "centrifuge-json":
                return False

            async def receive_matching(command_id: int, field: str, timeout_seconds: float) -> bool:
                deadline = time.monotonic() + timeout_seconds
                while time.monotonic() < deadline:
                    raw = await asyncio.wait_for(
                        ws.recv(),
                        timeout=max(0.1, deadline - time.monotonic()),
                    )
                    if isinstance(raw, bytes):
                        raw = raw.decode("utf-8", errors="replace")
                    for line in str(raw).splitlines() or [str(raw)]:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            frame = json.loads(line)
                        except Exception:
                            continue
                        if frame == {}:
                            await ws.send("{}")
                            continue
                        if not isinstance(frame, dict) or frame.get("id") != command_id:
                            continue
                        if isinstance(frame.get(field), dict):
                            return True
                        if "error" in frame:
                            return False
                return False

            await ws.send(json.dumps({
                "connect": {"name": "x4g-auto-egress-check"},
                "id": 1,
            }))
            if not await receive_matching(1, "connect", 10):
                return False

            await ws.send(json.dumps({
                "subscribe": {"channel": "orderbook:2", "recover": True},
                "id": 2,
            }))
            if not await receive_matching(2, "subscribe", 8):
                return False

            # An ACK alone can still be a half-working path. Require one real,
            # structurally valid public orderbook publication before admitting it.
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                raw = await asyncio.wait_for(
                    ws.recv(),
                    timeout=max(0.1, deadline - time.monotonic()),
                )
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8", errors="replace")
                for line in str(raw).splitlines() or [str(raw)]:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        frame = json.loads(line)
                    except Exception:
                        continue
                    if frame == {}:
                        await ws.send("{}")
                        continue
                    push = frame.get("push") if isinstance(frame, dict) else None
                    if not isinstance(push, dict) or push.get("channel") != "orderbook:2":
                        continue
                    publication = push.get("pub")
                    data = publication.get("data") if isinstance(publication, dict) else None
                    if (
                        isinstance(data, dict)
                        and isinstance(data.get("buys"), list)
                        and isinstance(data.get("sells"), list)
                    ):
                        return True
            return False
    except Exception:
        return False


async def _resolve_mtproto_candidate(
    host: str, port: int, secret: str, direct_client: httpx.AsyncClient
) -> dict | None:
    started = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=3.5
        )
        peer = writer.get_extra_info("peername")
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        if not peer or not _public_ip(str(peer[0])):
            return None
        ip = str(peer[0])
        geo = await _geoip_votes(direct_client, ip)
        if not geo["iran_confirmed"]:
            return None
        link = "https://t.me/proxy?" + urlencode({
            "server": host,
            "port": str(port),
            "secret": secret,
        })
        return {
            "host": host,
            "port": port,
            "ip": ip,
            "city": geo.get("city") or "Iran",
            "geoip": geo,
            "tcp_ms": round((time.monotonic() - started) * 1000),
            "link": link,
            "protocol": "MTProto",
            "telegram_handshake_verified": False,
        }
    except Exception:
        return None


def _parse_public_vless(content: str) -> tuple[str | None, list[dict]]:
    generated = None
    candidates = []
    seen = set()
    for raw in content.splitlines():
        line = raw.strip()
        if line.startswith("#") and "Generated:" in line:
            generated = line.split("Generated:", 1)[1].strip()
            continue
        if not line.startswith("vless://") or len(line) > 1100 or "{" in line or "}" in line:
            continue
        try:
            parsed = urlsplit(line)
            uid = parsed.username or ""
            host = parsed.hostname or ""
            port = parsed.port
            if not uid or not host or not port or not (1 <= port <= 65535):
                continue
            if not re.fullmatch(r"[0-9a-fA-F-]{16,64}", uid):
                continue
            key = (host.lower(), port, uid.lower())
            if key in seen:
                continue
            seen.add(key)
            candidates.append({
                "host": host,
                "port": port,
                "uri": line,
                "transport": (parse_qs(parsed.query).get("type") or ["unknown"])[0],
                "security": (parse_qs(parsed.query).get("security") or ["unknown"])[0],
                "verified_by_source": "source claims >=2/3 GeoIP votes",
                "connection_verified": False,
            })
        except Exception:
            continue
    return generated, candidates[:2]


async def _fetch_public_vless(direct_client: httpx.AsyncClient) -> tuple[str | None, list[dict]]:
    try:
        response = await direct_client.get(VLESS_SOURCE, timeout=8.0)
        response.raise_for_status()
        return _parse_public_vless(response.text)
    except Exception as exc:
        logger.warning("Public VLESS source fetch failed: %s", type(exc).__name__)
        return None, []


async def _scan_mtproto(direct_client: httpx.AsyncClient) -> list[dict]:
    try:
        response = await direct_client.get(MTPROTO_SOURCE, timeout=8.0)
        response.raise_for_status()
        lines = response.text.splitlines()
    except Exception as exc:
        logger.warning("MTProto source fetch failed: %s", type(exc).__name__)
        return []

    parsed = []
    seen = set()
    for line in lines:
        line = line.strip()
        if not line.startswith("https://t.me/proxy?"):
            continue
        try:
            query = parse_qs(urlsplit(line).query)
            host = (query.get("server") or [""])[0].strip()
            port = int((query.get("port") or ["0"])[0])
            secret = (query.get("secret") or [""])[0].strip()
            if not host or not secret or not (1 <= port <= 65535):
                continue
            key = (host.lower(), port, secret)
            if key in seen:
                continue
            seen.add(key)
            parsed.append((host, port, secret))
        except Exception:
            continue

    # Hostnames suggesting Iranian endpoints are tried first, but never treated
    # as country evidence; only independent GeoIP votes can label them Iranian.
    parsed.sort(key=lambda item: not any(
        marker in item[0].lower()
        for marker in ("ir", "tehran", "shomal", "foriran")
    ))
    parsed = parsed[:_MTPROTO_SCAN_LIMIT]
    semaphore = asyncio.Semaphore(6)

    async def bounded(item):
        async with semaphore:
            return await _resolve_mtproto_candidate(*item, direct_client)

    results = await asyncio.gather(*(bounded(item) for item in parsed))
    return sorted(
        [item for item in results if item],
        key=lambda row: row["tcp_ms"],
    )


async def scan_iran_proxies(force: bool = False) -> dict:
    """Discover and verify Iran HTTP proxies and Telegram-only MTProto endpoints."""
    global _scan_cache, _scan_cache_at
    now = time.monotonic()
    if not force and _scan_cache is not None and now - _scan_cache_at < _SCAN_TTL_SECONDS:
        return {**_scan_cache, "cached": True}

    async with _scan_lock:
        now = time.monotonic()
        if not force and _scan_cache is not None and now - _scan_cache_at < _SCAN_TTL_SECONDS:
            return {**_scan_cache, "cached": True}

        async with httpx.AsyncClient(
            timeout=_DIRECT_TIMEOUT,
            follow_redirects=False,
            trust_env=False,
            headers={"User-Agent": "X4G-Iran-Proxy-Discovery/1.0"},
        ) as direct_client:
            try:
                source_response = await direct_client.get(HTTP_PROXY_SOURCE, timeout=10.0)
                source_response.raise_for_status()
                source_payload = source_response.json()
            except Exception as exc:
                source_payload = []
                logger.warning("Iran HTTP proxy source fetch failed: %s", type(exc).__name__)

            candidates = _http_proxy_candidates(source_payload)
            vless_generated, vless_candidates = await _fetch_public_vless(direct_client)
            semaphore = asyncio.Semaphore(6)

            async def bounded(candidate):
                async with semaphore:
                    return await _test_http_proxy(candidate, direct_client)

            http_results = await asyncio.gather(*(bounded(candidate) for candidate in candidates))
            mtproto_results = await _scan_mtproto(direct_client)

        iran_http = [row for row in http_results if row.get("geoip", {}).get("iran_confirmed")]
        ramzinex_ready = [row for row in iran_http if row.get("ramzinex_ready")]
        ready_sort = lambda row: row.get("latency_ms", 999999)
        iran_http.sort(key=lambda row: (
            not row.get("ramzinex_ready"),
            ready_sort(row),
        ))
        ramzinex_ready.sort(key=ready_sort)
        report = {
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "source_http": HTTP_PROXY_SOURCE,
            "source_mtproto": MTPROTO_SOURCE,
            "source_vless": VLESS_SOURCE,
            "vless_source_generated": vless_generated,
            "vless_candidates": vless_candidates,
            "http_candidates": len(candidates),
            "http_tested": len(http_results),
            "http_diagnostics": [
                {
                    "proxy": row.get("proxy"),
                    "status": row.get("status"),
                    "error": row.get("error"),
                    "detail": row.get("detail"),
                    "exit_ip": row.get("exit_ip"),
                    "geoip_votes": {
                        name: value.get("country")
                        for name, value in row.get("geoip", {}).get("votes", {}).items()
                    },
                    "pairs_status": row.get("pairs_status"),
                    "orderbook_status": row.get("orderbook_status"),
                    "latency_ms": row.get("latency_ms"),
                }
                for row in http_results
            ],
            "iran_http_exits": iran_http,
            "ramzinex_ready": ramzinex_ready,
            "mtproto_iran_tcp": mtproto_results,
            "mtproto_note": "TCP and GeoIP checked; Telegram MTProto handshake not verified.",
        }
        _scan_cache = report
        _scan_cache_at = time.monotonic()
        return {**report, "cached": False}


# ── Runtime self-healing Ramzinex egress pool ──────────────────────────────────
# Public proxy lists are volatile. Keep a small pool of routes that have passed
# three independent GeoIP checks plus live Ramzinex pairs/orderbook GETs.
# A private, operator-supplied RAMZINEX_UPSTREAM_PROXY is optional and is tested
# by the exact same checks; it is never trusted merely because it is configured.
_RAMZINEX_PROXY_REFRESH_SECONDS = max(
    180, min(3600, int(os.environ.get("RAMZINEX_PROXY_REFRESH_SECONDS", "600")))
)
_RAMZINEX_PROXY_STARTUP_TIMEOUT = max(
    30, min(180, int(os.environ.get("RAMZINEX_PROXY_STARTUP_TIMEOUT", "150")))
)
_RAMZINEX_PROXY_POOL_SIZE = 5
_RAMZINEX_PROXY_RETRY_SECONDS = max(
    15, min(300, int(os.environ.get("RAMZINEX_PROXY_RETRY_SECONDS", "60")))
)
_RAMZINEX_HTTP_VERIFY_LIMIT = max(
    12, min(64, int(os.environ.get("RAMZINEX_HTTP_VERIFY_LIMIT", "48")))
)
_RAMZINEX_WS_VERIFY_LIMIT = max(4, min(16, int(os.environ.get("RAMZINEX_WS_VERIFY_LIMIT", "12"))))
_RAMZINEX_VLESS_VERIFY_LIMIT = max(1, min(20, int(os.environ.get("RAMZINEX_VLESS_SCAN_LIMIT", "12"))))
# Previously verified public endpoints are treated only as candidates. They are
# re-tested from scratch on every refresh and never trusted or used blindly.
_RAMZINEX_LAST_KNOWN_PROXY_CANDIDATES = (
    "http://80.191.46.62:1090",
    "http://2.179.95.57:8080",
    "http://185.129.213.210:8080",
)
_ramzinex_proxy_urls: list[str] = []
_ramzinex_proxy_checked_at = 0.0
_ramzinex_proxy_status: dict = {
    "state": "not_checked",
    "verified_count": 0,
    "candidate_count": 0,
    "http_ready_count": 0,
    "websocket_tested_count": 0,
    "websocket_ready_count": 0,
    "checked_at": None,
    "last_error": None,
}
_ramzinex_proxy_lock = asyncio.Lock()
_ramzinex_proxy_task: asyncio.Task | None = None


def _proxy_candidate_from_config(proxy_url: str) -> dict | None:
    try:
        parsed = urlsplit(proxy_url)
        if (
            parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or parsed.port is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
        ):
            return None
        return {
            "proxy": proxy_url,
            "ip": parsed.hostname,
            "port": parsed.port,
            "anonymity": "configured",
            "listed_city": "configured",
        }
    except Exception:
        return None


def _set_ramzinex_proxy_status(state: str, verified_count: int, error: str | None = None) -> None:
    _ramzinex_proxy_status.update({
        "state": state,
        "verified_count": verified_count,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "last_error": error,
    })


async def refresh_ramzinex_proxy_pool(force: bool = False) -> dict:
    """Refresh a short, verified failover pool without scanning unrelated protocols."""
    global _ramzinex_proxy_urls, _ramzinex_proxy_checked_at
    now = time.monotonic()
    if (
        not force
        and _ramzinex_proxy_checked_at
        and now - _ramzinex_proxy_checked_at < _RAMZINEX_PROXY_REFRESH_SECONDS
    ):
        return {**_ramzinex_proxy_status, "cached": True}

    async with _ramzinex_proxy_lock:
        now = time.monotonic()
        if (
            not force
            and _ramzinex_proxy_checked_at
            and now - _ramzinex_proxy_checked_at < _RAMZINEX_PROXY_REFRESH_SECONDS
        ):
            return {**_ramzinex_proxy_status, "cached": True}

        candidates: list[dict] = []
        configured = _proxy_candidate_from_config(UPSTREAM_PROXY) if UPSTREAM_PROXY else None
        if configured:
            candidates.append(configured)
        for known_proxy in _RAMZINEX_LAST_KNOWN_PROXY_CANDIDATES:
            candidate = _proxy_candidate_from_config(known_proxy)
            if candidate:
                candidate["anonymity"] = "previously-verified-recheck"
                candidate["listed_city"] = "unknown"
                candidates.append(candidate)

        source_error = None
        proxyspace_errors: list[str] = []
        vless_rows: list[dict] = []
        vless_candidate_count = 0
        async with httpx.AsyncClient(
            timeout=_DIRECT_TIMEOUT,
            follow_redirects=False,
            trust_env=False,
            headers={"User-Agent": "X4G-Ramzinex-AutoEgress/1.0", "Accept": "application/json"},
        ) as direct_client:
            # Active VLESS routes are revalidated first, then fresh Iranian-exit
            # candidates are started one at a time. The public source is only a
            # discovery hint; GeoIP + Ramzinex REST + Centrifuge checks are gates.
            try:
                active_vless = await _vless_egress_manager.active_candidates()
                discovered_vless = []
                if os.environ.get("RAMZINEX_VLESS_ENABLED", "true").strip().lower() not in ("0", "false", "no", "off"):
                    discovered_vless = await _vless_egress_manager.fetch_candidates(
                        direct_client, limit=_RAMZINEX_VLESS_VERIFY_LIMIT
                    )
                combined_vless = []
                seen_vless = set()
                for spec in active_vless + discovered_vless:
                    key = str(spec.get("key") or "")
                    if key and key not in seen_vless:
                        seen_vless.add(key)
                        combined_vless.append(spec)
                vless_candidate_count = len(combined_vless)
                for spec in combined_vless[:_RAMZINEX_VLESS_VERIFY_LIMIT]:
                    route = await _vless_egress_manager.start(spec)
                    if route is None:
                        continue
                    candidate = route.candidate()
                    candidate["key"] = route.key
                    row = await _test_http_proxy(candidate, direct_client)
                    if (
                        row.get("ramzinex_ready") is True
                        and row.get("geoip", {}).get("iran_confirmed") is True
                    ):
                        row["vless_route"] = True
                        row["vless_key"] = route.key
                        vless_rows.append(row)
                    else:
                        await _vless_egress_manager.stop(route.proxy_url)
            except Exception as exc:
                logger.warning("VLESS egress discovery failed type=%s", type(exc).__name__)

            try:
                source_response = await direct_client.get(HTTP_PROXY_SOURCE, timeout=12.0)
                source_response.raise_for_status()
                candidates.extend(_http_proxy_candidates(source_response.json()))
            except Exception as exc:
                source_error = type(exc).__name__
                logger.warning("Ramzinex auto-egress source fetch failed type=%s", source_error)

            async def fetch_proxyspace(url: str, label: str) -> list[dict]:
                try:
                    response = await direct_client.get(url, timeout=12.0)
                    response.raise_for_status()
                    return _proxyspace_candidates(
                        response.text if label == "http" else "",
                        response.text if label == "https" else "",
                    )
                except Exception as exc:
                    proxyspace_errors.append(f"{label}:{type(exc).__name__}")
                    logger.warning("ProxySpace %s candidate list unavailable type=%s", label, type(exc).__name__)
                    return []

            proxyspace_lists = await asyncio.gather(
                fetch_proxyspace(PROXYSPACE_IR_HTTP_SOURCE, "http"),
                fetch_proxyspace(PROXYSPACE_IR_HTTPS_SOURCE, "https"),
            )
            for rows_for_protocol in proxyspace_lists:
                candidates.extend(rows_for_protocol)

            unique: dict[str, dict] = {}
            for candidate in candidates:
                unique.setdefault(candidate["proxy"], candidate)
            # Keep configured and previously successful candidates first, then
            # recent country-filtered ProxySpace candidates, then Proxifly.
            priority = {
                "configured": 0,
                "previously-verified-recheck": 1,
                "proxyspace-http": 2,
                "proxyspace-https": 3,
            }
            candidates = sorted(
                unique.values(),
                key=lambda row: priority.get(row.get("anonymity"), 4),
            )[:_RAMZINEX_HTTP_VERIFY_LIMIT]
            semaphore = asyncio.Semaphore(6)

            async def bounded(candidate: dict) -> dict:
                async with semaphore:
                    return await _test_http_proxy(candidate, direct_client)

            rows = await asyncio.gather(*(bounded(candidate) for candidate in candidates))

        rows = vless_rows + rows
        http_ready = [
            row for row in rows
            if row.get("ramzinex_ready") is True
            and row.get("geoip", {}).get("iran_confirmed") is True
        ]
        http_ready.sort(key=lambda row: (
            not row.get("vless_route"),
            row.get("proxy") != UPSTREAM_PROXY,
            row.get("latency_ms", 999999),
        ))

        # REST-compatible open proxies aren't necessarily WebSocket-compatible.
        # Admit a route to the live pool only after a real Centrifuge handshake
        # and public orderbook subscription acknowledgement.
        ws_semaphore = asyncio.Semaphore(_RAMZINEX_PROXY_POOL_SIZE)

        async def verify_websocket(row: dict) -> dict | None:
            async with ws_semaphore:
                ok = await _test_ramzinex_websocket_proxy(str(row["proxy"]))
                if ok:
                    row["websocket_ready"] = True
                    return row
                if row.get("vless_route"):
                    await _vless_egress_manager.stop(str(row["proxy"]))
                return None

        ws_results = await asyncio.gather(*(
            verify_websocket(row) for row in http_ready[:_RAMZINEX_WS_VERIFY_LIMIT]
        ))
        ready = [row for row in ws_results if row]
        ready.sort(key=lambda row: (
            not row.get("vless_route"),
            row.get("proxy") != UPSTREAM_PROXY,
            row.get("latency_ms", 999999),
        ))
        selected = ready[:_RAMZINEX_PROXY_POOL_SIZE]
        await _vless_egress_manager.keep_only({
            str(row["proxy"]) for row in selected if row.get("vless_route")
        })
        _ramzinex_proxy_urls = [str(row["proxy"]) for row in selected]
        _ramzinex_proxy_checked_at = time.monotonic()

        if selected:
            state = "configured_and_discovered" if any(
                row.get("proxy") == UPSTREAM_PROXY for row in selected
            ) and len(selected) > 1 else (
                "configured" if selected[0].get("proxy") == UPSTREAM_PROXY else "discovered"
            )
            _set_ramzinex_proxy_status(state, len(selected), None)
            logger.info("Ramzinex egress pool refreshed: %s verified route(s)", len(selected))
        else:
            _set_ramzinex_proxy_status(
                "unavailable",
                0,
                "no_iran_proxy_passed_geoip_ramzinex_rest_and_centrifuge_websocket_checks"
                + (f";source={source_error}" if source_error else ""),
            )
            logger.warning("Ramzinex egress pool refresh found no verified route")

        _ramzinex_proxy_status.update({
            "candidate_count": len(candidates),
            "http_ready_count": len(http_ready),
            "websocket_tested_count": min(len(http_ready), _RAMZINEX_WS_VERIFY_LIMIT),
            "websocket_ready_count": len(ready),
            "vless_candidate_count": vless_candidate_count,
            "vless_rest_ready_count": len(vless_rows),
            "vless_websocket_ready_count": sum(1 for row in ready if row.get("vless_route")),
        })
        _ramzinex_proxy_status["proxyspace_source_errors"] = proxyspace_errors
        _ramzinex_proxy_status["http_candidate_limit"] = _RAMZINEX_HTTP_VERIFY_LIMIT
        _ramzinex_proxy_status["vless_candidate_limit"] = _RAMZINEX_VLESS_VERIFY_LIMIT
        return {**_ramzinex_proxy_status, "cached": False}


async def _get_ramzinex_proxy_urls(force_refresh: bool = False) -> list[str]:
    now = time.monotonic()
    expired = (
        not _ramzinex_proxy_checked_at
        or now - _ramzinex_proxy_checked_at >= _RAMZINEX_PROXY_REFRESH_SECONDS
    )
    if force_refresh or expired:
        await refresh_ramzinex_proxy_pool(force=True)
    return list(_ramzinex_proxy_urls)


async def _mark_ramzinex_proxy_failed(proxy_url: str) -> None:
    global _ramzinex_proxy_urls, _ramzinex_proxy_checked_at
    async with _ramzinex_proxy_lock:
        if proxy_url in _ramzinex_proxy_urls:
            _ramzinex_proxy_urls = [item for item in _ramzinex_proxy_urls if item != proxy_url]
        _ramzinex_proxy_checked_at = 0.0
        _set_ramzinex_proxy_status(
            "degraded" if _ramzinex_proxy_urls else "unavailable",
            len(_ramzinex_proxy_urls),
            "a_previously_verified_route_failed",
        )
    if proxy_url.startswith("socks5://127.0.0.1:"):
        await _vless_egress_manager.stop(proxy_url)


async def _ramzinex_proxy_maintenance_loop() -> None:
    while True:
        # Retry quickly while no Iranian WebSocket route exists; once the pool
        # is healthy, return to the normal 10-minute refresh cadence.
        delay = _RAMZINEX_PROXY_REFRESH_SECONDS if _ramzinex_proxy_urls else _RAMZINEX_PROXY_RETRY_SECONDS
        await asyncio.sleep(delay)
        try:
            await refresh_ramzinex_proxy_pool(force=True)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("Ramzinex proxy maintenance failed type=%s", type(exc).__name__)
            _set_ramzinex_proxy_status("unavailable", len(_ramzinex_proxy_urls), type(exc).__name__)


async def start_proxy_manager() -> None:
    """Warm the verified route pool, then keep it refreshed for the app lifetime."""
    global _ramzinex_proxy_task
    if _ramzinex_proxy_task is None or _ramzinex_proxy_task.done():
        # Complete one bounded initial scan before the application is marked ready.
        # This prevents the first WebSocket handshake from waiting behind a 30-60s scan.
        startup_timeout = _RAMZINEX_PROXY_STARTUP_TIMEOUT
        try:
            await asyncio.wait_for(
                refresh_ramzinex_proxy_pool(force=False),
                timeout=startup_timeout,
            )
        except asyncio.TimeoutError:
            _set_ramzinex_proxy_status(
                "starting",
                len(_ramzinex_proxy_urls),
                "initial_proxy_scan_timeout",
            )
            logger.warning("Ramzinex initial proxy scan exceeded %s seconds", startup_timeout)
        except Exception as exc:
            _set_ramzinex_proxy_status(
                "unavailable",
                len(_ramzinex_proxy_urls),
                type(exc).__name__,
            )
            logger.warning("Ramzinex initial proxy scan failed type=%s", type(exc).__name__)

        _ramzinex_proxy_task = asyncio.create_task(
            _ramzinex_proxy_maintenance_loop(),
            name="ramzinex-proxy-maintenance",
        )


async def stop_proxy_manager() -> None:
    global _ramzinex_proxy_task
    task = _ramzinex_proxy_task
    _ramzinex_proxy_task = None
    if task is not None:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    await _vless_egress_manager.stop_all()


async def _get_egress_ip_via_pool() -> dict:
    last_error = None
    for cycle in range(2):
        proxy_urls = await _get_ramzinex_proxy_urls(force_refresh=(cycle > 0))
        for proxy_url in proxy_urls:
            try:
                async with httpx.AsyncClient(
                    proxies=proxy_url,
                    timeout=TIMEOUT,
                    follow_redirects=False,
                    trust_env=False,
                ) as client:
                    response = await client.get(IP_ECHO_URL)
                    if response.status_code == 200:
                        payload = response.json()
                        return {
                            "http_status": response.status_code,
                            "ip": payload.get("ip") if isinstance(payload, dict) else None,
                        }
                    last_error = httpx.ConnectError(f"IP echo returned HTTP {response.status_code}")
            except httpx.RequestError as exc:
                last_error = exc
            await _mark_ramzinex_proxy_failed(proxy_url)
    if last_error:
        raise last_error
    raise HTTPException(status_code=503, detail="No verified Iran egress route is available")


async def build_daily_proxy_report(force: bool = False) -> str:
    report = await scan_iran_proxies(force=force)
    checked = report.get("checked_at", "")
    try:
        checked_display = datetime.fromisoformat(checked).astimezone(ZoneInfo("Asia/Baku")).strftime("%Y-%m-%d %H:%M")
    except Exception:
        checked_display = checked or "نامشخص"

    lines = [
        "🇮🇷 <b>گزارش روزانهٔ پروکسی‌های ایران</b>",
        f"زمان بررسی: <code>{html.escape(checked_display)}</code>",
        "",
        f"پروکسی‌های HTTP/HTTPS بررسی‌شده: <b>{report.get('http_tested', 0)}</b>",
        f"خروجی ایران با حداقل ۲ تأیید GeoIP: <b>{len(report.get('iran_http_exits', []))}</b>",
        f"قابل‌استفاده برای API عمومی رمزینکس: <b>{len(report.get('ramzinex_ready', []))}</b>",
    ]

    ready = report.get("ramzinex_ready", [])[:5]
    if ready:
        lines.extend(["", "✅ <b>پروکسی‌های تأییدشده برای رمزینکس</b>"])
        for index, row in enumerate(ready, 1):
            city = html.escape(str(row.get("geoip", {}).get("city") or "ایران"))
            endpoint = html.escape(f"{row.get('ip')}:{row.get('port')}")
            latency = row.get("latency_ms", "?")
            lines.append(
                f"{index}) <code>{endpoint}</code> — {city} — {latency} ms "
                f"(Pairs {row.get('pairs_status')}, Orderbook {row.get('orderbook_status')})"
            )
    else:
        lines.extend([
            "",
            "⚠️ امروز هیچ HTTP/HTTPS پروکسی با تأیید خروجی ایران و پاسخ موفق هر دو API رمزینکس پیدا نشد.",
        ])

    other_exits = [
        row for row in report.get("iran_http_exits", [])
        if not row.get("ramzinex_ready")
    ][:3]
    if other_exits:
        lines.extend(["", "🌐 <b>خروجی ایران؛ هنوز برای رمزینکس تأیید نشده</b>"])
        for index, row in enumerate(other_exits, 1):
            lines.append(
                f"{index}) <code>{html.escape(str(row.get('ip')))}:{row.get('port')}</code> "
                f"— API رمزینکس: {row.get('pairs_status', 'نامشخص')}/"
                f"{row.get('orderbook_status', 'نامشخص')}"
            )

    vless = report.get("vless_candidates", [])[:3]
    if vless:
        lines.extend([
            "",
            "🧩 <b>کاندیدهای عمومی VLESS</b>",
            "<i>فهرست مبدأ ادعای تأیید GeoIP دارد؛ اتصال Xray و کارکرد عملی هنوز آزمایش نشده است.</i>",
        ])
        if report.get("vless_source_generated"):
            lines.append(f"تاریخ مبدأ: <code>{html.escape(str(report['vless_source_generated']))}</code>")
        for index, row in enumerate(vless, 1):
            lines.append(
                f"{index}) <code>{html.escape(str(row.get('uri', '')))}</code>"
            )

    mtproto = report.get("mtproto_iran_tcp", [])[:5]
    if mtproto:
        lines.extend([
            "",
            "📨 <b>پروکسی‌های MTProto ایران برای خود تلگرام</b>",
            "<i>فقط TCP و موقعیت IP بررسی شده؛ اتصال کامل پروتکل تلگرام تضمین نشده است.</i>",
        ])
        for index, row in enumerate(mtproto, 1):
            link = html.escape(str(row.get("link", "")), quote=True)
            host = html.escape(str(row.get("host", "")))
            city = html.escape(str(row.get("city", "ایران")))
            lines.append(f'{index}) <a href="{link}">{host}:{row.get("port")}</a> — {city}')

    lines.extend([
        "",
        "<i>هشدار امنیتی: پروکسی‌های عمومی را برای ورود، رمز عبور، کیف پول یا دادهٔ خصوصی استفاده نکن؛ فقط برای GETهای عمومی و آزمایشی.</i>",
        f'<a href="{html.escape(HTTP_PROXY_SOURCE, quote=True)}">منبع فهرست HTTP/HTTPS</a> | '
        f'<a href="{html.escape(MTPROTO_SOURCE, quote=True)}">منبع MTProto</a>',
    ])
    return "\n".join(lines)


@app.get("/ready")
async def ready() -> JSONResponse:
    """Readiness check for monitoring; 503 until a usable WebSocket route exists."""
    healthy = bool(TOKEN and len(TOKEN) >= 32 and _ramzinex_proxy_urls)
    payload = {
        "ready": healthy,
        "relay_token_configured": len(TOKEN) >= 32,
        "proxy_pool_state": _ramzinex_proxy_status.get("state"),
        "verified_routes": len(_ramzinex_proxy_urls),
    }
    return JSONResponse(payload, status_code=200 if healthy else 503)


@app.get("/health")
async def health() -> dict:
    return {
        "ok": True,
        "service": "x4g-ramzinex-readonly-relay",
        "upstream_proxy_configured": _proxy_is_valid(),
        "upstream_proxy_ready": bool(_ramzinex_proxy_urls),
        "proxy_pool": {
            "state": _ramzinex_proxy_status.get("state"),
            "verified_count": len(_ramzinex_proxy_urls),
            "candidate_count": _ramzinex_proxy_status.get("candidate_count", 0),
            "http_ready_count": _ramzinex_proxy_status.get("http_ready_count", 0),
            "websocket_tested_count": _ramzinex_proxy_status.get("websocket_tested_count", 0),
            "websocket_ready_count": _ramzinex_proxy_status.get("websocket_ready_count", 0),
            "checked_at": _ramzinex_proxy_status.get("checked_at"),
            "last_error": _ramzinex_proxy_status.get("last_error"),
            "refresh_seconds": _RAMZINEX_PROXY_REFRESH_SECONDS,
        },
        "relay_token_configured": len(TOKEN) >= 32,
        "mode": "read-only, allow-listed, auto-failover",
    }


def _valid_ws_token(supplied: str) -> bool:
    return bool(TOKEN) and hmac.compare_digest(supplied or "", TOKEN)


def _is_allowed_centrifuge_frame(frame: str) -> bool:
    """Allow only Centrifuge connect/subscribe/unsubscribe for public market channels."""
    if not isinstance(frame, str):
        return False
    try:
        if len(frame.encode("utf-8")) > WS_MAX_MESSAGE_BYTES:
            return False
    except Exception:
        return False

    lines = [line.strip() for line in frame.splitlines() if line.strip()]
    if not lines or len(lines) > 32:
        return False

    for line in lines:
        try:
            command = json.loads(line)
        except Exception:
            return False
        if command == {}:
            # Centrifuge application-level ping/pong.
            continue
        if not isinstance(command, dict):
            return False

        command_names = [name for name in ("connect", "subscribe", "unsubscribe") if name in command]
        if len(command_names) != 1 or set(command) - {"id", command_names[0]}:
            return False

        name = command_names[0]
        body = command.get(name)
        if not isinstance(body, dict):
            return False

        if name == "connect":
            # The relay never forwards client-supplied auth tokens or server-side/private subscriptions.
            if set(body) - {"name", "version"}:
                return False
        elif name == "subscribe":
            if set(body) - {"channel", "recover", "delta", "offset", "epoch"}:
                return False
            channel = body.get("channel")
            if not isinstance(channel, str) or not _PUBLIC_WS_CHANNEL.fullmatch(channel):
                return False
            if body.get("delta") not in (None, "fossil"):
                return False
        elif name == "unsubscribe":
            if set(body) == {"sid"}:
                if not isinstance(body.get("sid"), (str, int)):
                    return False
            elif set(body) == {"channel"}:
                channel = body.get("channel")
                if not isinstance(channel, str) or not _PUBLIC_WS_CHANNEL.fullmatch(channel):
                    return False
            else:
                return False

    return True


async def _ws_connection_acquire(client_ip: str) -> bool:
    global _ws_active_total
    async with _ws_active_lock:
        if _ws_active_total >= WS_MAX_CONNECTIONS_TOTAL:
            return False
        if _ws_active_by_ip[client_ip] >= WS_MAX_CONNECTIONS_PER_IP:
            return False
        _ws_active_by_ip[client_ip] += 1
        _ws_active_total += 1
        return True


async def _ws_connection_release(client_ip: str) -> None:
    global _ws_active_total
    async with _ws_active_lock:
        if _ws_active_by_ip.get(client_ip, 0) > 0:
            _ws_active_by_ip[client_ip] -= 1
            _ws_active_total = max(0, _ws_active_total - 1)
        if _ws_active_by_ip.get(client_ip, 0) <= 0:
            _ws_active_by_ip.pop(client_ip, None)


async def _ws_client_to_upstream(websocket: WebSocket, upstream) -> None:
    while True:
        event = await websocket.receive()
        if event.get("type") == "websocket.disconnect":
            return
        message = event.get("text")
        if message is None or not _is_allowed_centrifuge_frame(message):
            await websocket.close(code=1008, reason="public market channels are read-only")
            return
        await upstream.send(message)


async def _ws_upstream_to_client(websocket: WebSocket, upstream) -> None:
    async for message in upstream:
        if isinstance(message, str):
            await websocket.send_text(message)
        else:
            await websocket.send_bytes(message)


async def _run_public_ws_tunnel(websocket: WebSocket, proxy_url: str) -> str:
    async with websockets.connect(
        WS_ENDPOINT,
        proxy=proxy_url,
        subprotocols=["centrifuge-json"],
        open_timeout=12,
        close_timeout=4,
        ping_interval=20,
        ping_timeout=20,
        max_size=WS_MAX_MESSAGE_BYTES,
        compression=None,
    ) as upstream:
        if upstream.subprotocol != "centrifuge-json":
            raise RuntimeError("Ramzinex did not negotiate centrifuge-json")
        await websocket.accept(subprotocol="centrifuge-json")
        client_task = asyncio.create_task(_ws_client_to_upstream(websocket, upstream))
        upstream_task = asyncio.create_task(_ws_upstream_to_client(websocket, upstream))
        tasks = {client_task, upstream_task}
        try:
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

        if upstream_task in done:
            error = upstream_task.exception()
            if error:
                raise error
            return "upstream_closed"

        if client_task in done:
            error = client_task.exception()
            if error:
                raise error
            return "client_closed"

        return "closed"


@app.websocket("/ws")
async def ramzinex_public_websocket(websocket: WebSocket):
    """Authenticated, read-only Centrifuge tunnel with verified proxy failover."""
    supplied = websocket.headers.get("x-relay-token", "")
    if not _valid_ws_token(supplied):
        await websocket.close(code=1008)
        return
    try:
        _require_config()
        await _rate_check(websocket)
    except HTTPException:
        await websocket.close(code=1013)
        return

    client_ip = websocket.client.host if websocket.client else "unknown"
    if not await _ws_connection_acquire(client_ip):
        await websocket.close(code=1013)
        return

    try:
        # If a route dies between scheduled scans, mark it bad and try the next.
        # If every route fails, force one fresh discovery before refusing service.
        for cycle in range(2):
            proxy_urls = await _get_ramzinex_proxy_urls(force_refresh=(cycle > 0))
            if not proxy_urls:
                break
            for proxy_url in proxy_urls:
                try:
                    outcome = await _run_public_ws_tunnel(websocket, proxy_url)
                    if outcome == "upstream_closed":
                        await _mark_ramzinex_proxy_failed(proxy_url)
                        if (
                            websocket.client_state == WebSocketState.CONNECTED
                            and websocket.application_state == WebSocketState.CONNECTED
                        ):
                            await websocket.close(code=1011, reason="upstream reconnect required")
                    return
                except WebSocketDisconnect:
                    return
                except Exception as exc:
                    # A handshake error is safe to fail over before accepting the
                    # downstream socket. After accept, the client must reconnect.
                    await _mark_ramzinex_proxy_failed(proxy_url)
                    logger.warning(
                        "Ramzinex WebSocket route failed type=%s accepted=%s",
                        type(exc).__name__,
                        websocket.application_state == WebSocketState.CONNECTED,
                    )
                    if websocket.application_state == WebSocketState.CONNECTED:
                        try:
                            await websocket.close(code=1011, reason="upstream unavailable; reconnect")
                        except Exception:
                            pass
                        return

        if websocket.application_state != WebSocketState.CONNECTED:
            await websocket.close(code=1013, reason="no verified Ramzinex egress route")
    except Exception as exc:
        logger.warning(
            "Ramzinex WebSocket setup failed type=%s pool_state=%s",
            type(exc).__name__,
            _ramzinex_proxy_status.get("state"),
        )
        if websocket.application_state != WebSocketState.CONNECTED:
            try:
                await websocket.close(code=1013, reason="Ramzinex route discovery failed")
            except Exception:
                pass
        elif websocket.client_state == WebSocketState.CONNECTED:
            try:
                await websocket.close(code=1011, reason="upstream unavailable; reconnect")
            except Exception:
                pass
    finally:
        await _ws_connection_release(client_ip)


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
            egress = await _get_egress_ip_via_pool()
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
        return await _get_egress_ip_via_pool()
    except HTTPException:
        raise
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Egress IP lookup timed out")
    except httpx.RequestError:
        raise HTTPException(status_code=502, detail="Egress IP lookup failed")

