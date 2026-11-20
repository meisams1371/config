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
from typing import Deque
from urllib.parse import parse_qs, urlencode, urlsplit

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
    for attempt in range(3):
        try:
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
        except httpx.RequestError:
            if attempt >= 2:
                raise
            # The tested public Iran proxy has occasional transient connection
            # failures, so retry the read-only request twice before giving up.
            await asyncio.sleep(0.4 * (attempt + 1))


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
MTPROTO_SOURCE = (
    "https://raw.githubusercontent.com/Kolandone/v2raycollector/main/proxy.txt"
)
IP_ECHO_URL = "https://api.ipify.org?format=json"
RAMZINEX_PAIRS_URL = BASE + "/exchange/api/v1.0/exchange/pairs/2"
RAMZINEX_ORDERBOOK_URL = BASE + "/exchange/api/v1.0/exchange/orderbooks/2/buys_sells"
_scan_cache: dict | None = None
_scan_cache_at = 0.0
_scan_lock = asyncio.Lock()
_SCAN_TTL_SECONDS = 1800
_HTTP_SCAN_LIMIT = max(8, min(36, int(os.environ.get("IRAN_PROXY_SCAN_LIMIT", "24"))))
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
            semaphore = asyncio.Semaphore(6)

            async def bounded(candidate):
                async with semaphore:
                    return await _test_http_proxy(candidate, direct_client)

            http_results = await asyncio.gather(*(bounded(candidate) for candidate in candidates))
            mtproto_results = await _scan_mtproto(direct_client)

        iran_http = [row for row in http_results if row.get("geoip", {}).get("iran_confirmed")]
        ramzinex_ready = [row for row in iran_http if row.get("ramzinex_ready")]
        iran_http.sort(key=lambda row: (
            not row.get("ramzinex_ready"),
            row.get("latency_ms", 999999),
        ))
        report = {
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "source_http": HTTP_PROXY_SOURCE,
            "source_mtproto": MTPROTO_SOURCE,
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


async def build_daily_proxy_report(force: bool = False) -> str:
    report = await scan_iran_proxies(force=force)
    checked = report.get("checked_at", "")
    try:
        checked_display = datetime.fromisoformat(checked).astimezone().strftime("%Y-%m-%d %H:%M")
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
