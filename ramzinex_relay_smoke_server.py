from fastapi import FastAPI

from relay_app import (
    app as relay_app,
    start_proxy_manager,
    stop_proxy_manager,
)

app = FastAPI(title="Ramzinex relay CI smoke host")
app.mount("/", relay_app)


@app.on_event("startup")
async def startup() -> None:
    await start_proxy_manager()


@app.on_event("shutdown")
async def shutdown() -> None:
    await stop_proxy_manager()
