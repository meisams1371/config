import os
import time

from fastapi import FastAPI

from relay_app import (
    app as relay_app,
    start_proxy_manager,
    stop_proxy_manager,
    _ramzinex_proxy_urls,
    _set_ramzinex_proxy_status,
)
from relay_app import _ramzinex_proxy_checked_at as _initial_checked_at

# The preceding CI stage has already verified these routes with a real
# Centrifuge connect, orderbook subscribe ACK, and live orderbook publication.
# Seed that ephemeral same-run pool so the smoke process doesn't repeat a
# slow public-proxy discovery scan and doesn't trust stale routes across runs.
_seeded_routes = [
    item.strip()
    for item in os.environ.get("RAMZINEX_WS_HTTP_PROXIES", "").split(",")
    if item.strip()
]
if _seeded_routes:
    _ramzinex_proxy_urls.extend(_seeded_routes)
    import relay_app
    relay_app._ramzinex_proxy_checked_at = time.monotonic()
    _set_ramzinex_proxy_status("ci_preverified", len(_seeded_routes))

app = FastAPI(title="Ramzinex relay CI smoke host")
app.mount("/", relay_app)


@app.on_event("startup")
async def startup() -> None:
    await start_proxy_manager()


@app.on_event("shutdown")
async def shutdown() -> None:
    await stop_proxy_manager()
