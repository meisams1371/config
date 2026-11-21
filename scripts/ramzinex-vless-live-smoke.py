from __future__ import annotations

import asyncio
import json

import httpx

import relay_app
from vless_egress import manager


async def run() -> int:
    candidates_seen = 0
    xray_started = 0
    iran_confirmed = 0
    rest_ready = 0
    websocket_ready = 0
    kept: set[str] = set()

    async with httpx.AsyncClient(
        timeout=relay_app._DIRECT_TIMEOUT,
        follow_redirects=False,
        trust_env=False,
        headers={"User-Agent": "X4G-Ramzinex-VLESS-Live-Smoke/1.0"},
    ) as direct:
        candidates = await manager.fetch_candidates(
            direct, limit=relay_app._RAMZINEX_VLESS_VERIFY_LIMIT
        )
        candidates_seen = len(candidates)

        for spec in candidates:
            route = await manager.start(spec)
            if route is None:
                continue
            xray_started += 1
            candidate = route.candidate()
            candidate["key"] = route.key

            result = await relay_app._test_http_proxy(candidate, direct)
            if result.get("geoip", {}).get("iran_confirmed") is True:
                iran_confirmed += 1
            if not (
                result.get("ramzinex_ready") is True
                and result.get("geoip", {}).get("iran_confirmed") is True
            ):
                await manager.stop(route.proxy_url)
                continue

            rest_ready += 1
            if await relay_app._test_ramzinex_websocket_proxy(route.proxy_url):
                websocket_ready += 1
                kept.add(route.proxy_url)
                if websocket_ready >= relay_app._RAMZINEX_PROXY_POOL_SIZE:
                    break
            else:
                await manager.stop(route.proxy_url)

    await manager.keep_only(kept)
    report = {
        "source_candidate_count": candidates_seen,
        "xray_processes_started": xray_started,
        "iran_geoip_confirmed": iran_confirmed,
        "ramzinex_rest_ready": rest_ready,
        "centrifuge_websocket_ready": websocket_ready,
        "selected_verified_routes": len(kept),
        "raw_configs_logged": False,
    }
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    await manager.stop_all()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run()))
