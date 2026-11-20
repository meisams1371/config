import asyncio
import os
import time
from datetime import datetime, timezone

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
import httpx

app = FastAPI(title="Ramzinex Egress Probe", docs_url=None, redoc_url=None)
TOKEN = os.environ.get("RADAR_RELAY_TOKEN", "")
BASE = "https://publicapi.ramzinex.com"
TIMEOUT = httpx.Timeout(12.0, connect=5.0)
_cache = None
_cache_at = 0.0
_lock = asyncio.Lock()

def auth(value):
    if not TOKEN or value != "Bearer " + TOKEN:
        raise HTTPException(status_code=401, detail="unauthorized")

@app.get("/health")
async def health():
    return {"ok": True, "service": "ramzinex-egress-probe"}

def item_count(data):
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        for key in ("data", "results", "pairs", "items"):
            if isinstance(data.get(key), list):
                return len(data[key])
    return None

async def fetch_json(client, name, path):
    try:
        response = await client.get(
            BASE + path,
            headers={"Accept": "application/json", "User-Agent": "RamzinexRadar-EgressProbe/1.0"}
        )
        try:
            payload = response.json()
            valid_json = True
        except Exception:
            payload, valid_json = None, False
        return {
            "name": name,
            "http_status": response.status_code,
            "valid_json": valid_json,
            "items": item_count(payload) if valid_json else None,
            "top_level_keys": list(payload.keys())[:12] if isinstance(payload, dict) else None,
            "body_sample": None if response.status_code == 200 else response.text[:180]
        }
    except Exception as exc:
        return {"name": name, "error": type(exc).__name__}

@app.get("/radar/probe")
async def probe():
    global _cache, _cache_at
    now = time.monotonic()
    if _cache is not None and now - _cache_at < 60:
        return {"cached": True, **_cache}
    async with _lock:
        now = time.monotonic()
        if _cache is not None and now - _cache_at < 60:
            return {"cached": True, **_cache}
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False) as client:
            results = await asyncio.gather(
                fetch_json(client, "pairs", "/exchange/api/v1.0/exchange/pairs"),
                fetch_json(client, "prices", "/exchange/api/exchange/prices"),
                fetch_json(client, "orderbook_pair_2", "/exchange/api/v1.0/exchange/orderbooks/2/buys_sells"),
            )
            try:
                geo_response = await client.get("https://ipwho.is/")
                geo = geo_response.json()
                egress = {k: geo.get(k) for k in ("success", "ip", "country", "country_code", "region", "city", "connection")}
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
async def orderbook(pair_id: int, authorization: str = Header(default="")):
    auth(authorization)
    if pair_id < 1:
        raise HTTPException(status_code=400, detail="invalid pair id")
    path = f"/exchange/api/v1.0/exchange/orderbooks/{pair_id}/buys_sells"
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False) as client:
        response = await client.get(BASE + path, headers={"Accept": "application/json", "User-Agent": "RamzinexRadar/1.0"})
    try:
        payload = response.json()
    except Exception:
        payload = response.text[:1000]
    return JSONResponse(status_code=response.status_code, content={"http_status": response.status_code, "body": payload})

@app.get("/radar/egress")
async def egress(authorization: str = Header(default="")):
    auth(authorization)
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        response = await client.get("https://ipwho.is/")
        geo = response.json()
    return {k: geo.get(k) for k in ("success", "ip", "type", "continent", "country", "country_code", "region", "city", "connection")}
