import os, re
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
import httpx

app = FastAPI(title="Ramzinex Egress Probe", docs_url=None, redoc_url=None)
TOKEN = os.environ.get("RADAR_RELAY_TOKEN", "")
BASE = "https://publicapi.ramzinex.com"
TIMEOUT = httpx.Timeout(12.0, connect=5.0)

def auth(value):
    if not TOKEN or value != "Bearer " + TOKEN:
        raise HTTPException(status_code=401, detail="unauthorized")

@app.get("/health")
async def health():
    return {"ok": True, "service": "ramzinex-egress-probe"}

@app.get("/radar/probe")
async def probe(authorization: str = Header(default="")):
    auth(authorization)
    out = {}
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False) as c:
        for key, path in [
            ("pairs", "/api/v1.0/exchange/pairs"),
            ("currencies", "/api/v1.0/currencies"),
            ("prices", "/api/v1.0/exchange/prices")
        ]:
            try:
                r = await c.get(BASE + path, headers={"Accept":"application/json","User-Agent":"RamzinexRadar/1.0"})
                try:
                    data = r.json()
                    count = len(data) if isinstance(data, list) else (len(data.get("data", [])) if isinstance(data, dict) and isinstance(data.get("data"), list) else None)
                    valid_json = True
                except Exception:
                    count, valid_json = None, False
                out[key] = {"status": r.status_code, "valid_json": valid_json, "items": count, "sample": (r.text[:180] if r.status_code != 200 else None)}
            except Exception as e:
                out[key] = {"error": type(e).__name__}
    return out

@app.get("/radar/orderbooks/{pair_id}")
async def orderbook(pair_id: int, authorization: str = Header(default="")):
    auth(authorization)
    if pair_id < 1:
        raise HTTPException(status_code=400, detail="invalid pair id")
    path = f"/api/v1.0/exchange/orderbooks/{pair_id}"
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False) as c:
        r = await c.get(BASE + path, headers={"Accept":"application/json","User-Agent":"RamzinexRadar/1.0"})
    return JSONResponse(status_code=r.status_code, content={"status":r.status_code,"content_type":r.headers.get("content-type",""),"body":r.json() if "json" in r.headers.get("content-type","") else r.text[:1000]})

@app.get("/radar/egress")
async def egress(authorization: str = Header(default="")):
    auth(authorization)
    async with httpx.AsyncClient(timeout=TIMEOUT) as c:
        r = await c.get("https://ipwho.is/")
        j = r.json()
    return {k:j.get(k) for k in ("success","ip","type","continent","country","country_code","region","city","connection")}
