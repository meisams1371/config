import os
import time

from fastapi import FastAPI

import relay_app as relay_module

# The preceding CI stage has already verified these routes with a real
# Centrifuge connect, orderbook subscribe ACK, and live orderbook publication.
# Seed that ephemeral same-run pool so this process doesn't repeat a slow scan.
_seeded_routes = [
    item.strip()
    for item in os.environ.get("RAMZINEX_WS_HTTP_PROXIES", "").split(",")
    if item.strip()
]
if _seeded_routes:
    relay_module._ramzinex_proxy_urls[:] = _seeded_routes
    relay_module._ramzinex_proxy_checked_at = time.monotonic()
    relay_module._set_ramzinex_proxy_status("ci_preverified", len(_seeded_routes))

app = FastAPI(title="Ramzinex relay CI smoke host")
app.mount("/", relay_module.app)


@app.on_event("startup")
async def startup() -> None:
    await relay_module.start_proxy_manager()


@app.on_event("shutdown")
async def shutdown() -> None:
    await relay_module.stop_proxy_manager()
