from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request

import websockets

TOKEN = "ci-only-ramzinex-relay-token-not-a-production-secret-2026"
CHANNELS = ("orderbook:2", "orderbook:11", "last-trades:11")


def reserve_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def unpack_frames(raw: str | bytes) -> list[dict]:
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    frames = []
    for line in raw.splitlines() or [raw]:
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
            if isinstance(item, dict):
                frames.append(item)
        except json.JSONDecodeError:
            continue
    return frames


async def run_smoke(uri: str) -> dict:
    ack_ids = {2: "orderbook:2", 3: "orderbook:11", 4: "last-trades:11"}
    acknowledged: set[int] = set()
    publications: dict[str, int] = {channel: 0 for channel in CHANNELS}
    orderbook_shape_ok = False

    async with websockets.connect(
        uri,
        subprotocols=["centrifuge-json"],
        additional_headers={"X-Relay-Token": TOKEN},
        open_timeout=12,
        close_timeout=4,
        ping_interval=None,
        proxy=None,
        max_size=64 * 1024,
        compression=None,
    ) as ws:
        if ws.subprotocol != "centrifuge-json":
            raise RuntimeError("Relay did not negotiate centrifuge-json subprotocol")

        await ws.send(json.dumps({"connect": {"name": "python-relay-smoke"}, "id": 1}))
        connect_deadline = time.monotonic() + 18
        connected = False
        while time.monotonic() < connect_deadline and not connected:
            raw = await asyncio.wait_for(ws.recv(), timeout=max(0.1, connect_deadline - time.monotonic()))
            if isinstance(raw, str) and raw.strip() == "{}":
                await ws.send("{}")
                continue
            for frame in unpack_frames(raw):
                if frame.get("id") == 1 and isinstance(frame.get("connect"), dict):
                    connected = True
                    break
                if frame.get("id") == 1 and "error" in frame:
                    raise RuntimeError("Centrifuge rejected connect command")

        if not connected:
            raise TimeoutError("No Centrifuge connect acknowledgement through the relay")

        for command_id, channel in ack_ids.items():
            subscribe = {"channel": channel, "recover": True}
            if channel == "last-trades:11":
                subscribe["delta"] = "fossil"
            await ws.send(json.dumps({"subscribe": subscribe, "id": command_id}))

        deadline = time.monotonic() + 24
        while time.monotonic() < deadline:
            if len(acknowledged) == len(ack_ids) and sum(publications.values()) > 0:
                break
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=max(0.1, deadline - time.monotonic()))
            except asyncio.TimeoutError:
                break

            if isinstance(raw, str) and raw.strip() == "{}":
                await ws.send("{}")
                continue

            for frame in unpack_frames(raw):
                frame_id = frame.get("id")
                if frame_id in ack_ids and isinstance(frame.get("subscribe"), dict):
                    acknowledged.add(frame_id)
                push = frame.get("push")
                if isinstance(push, dict) and isinstance(push.get("pub"), dict):
                    channel = push.get("channel")
                    if channel in publications:
                        publications[channel] += 1
                        data = push["pub"].get("data")
                        if (
                            channel.startswith("orderbook:")
                            and isinstance(data, dict)
                            and isinstance(data.get("buys"), list)
                            and isinstance(data.get("sells"), list)
                        ):
                            orderbook_shape_ok = True

        result = {
            "connected": connected,
            "subscribed_channels": [ack_ids[i] for i in sorted(acknowledged)],
            "publication_counts": publications,
            "orderbook_payload_shape_confirmed": orderbook_shape_ok,
            "all_subscriptions_acknowledged": len(acknowledged) == len(ack_ids),
            "live_publication_received": sum(publications.values()) > 0,
        }

        if not result["all_subscriptions_acknowledged"]:
            raise RuntimeError("Not all public channel subscriptions were acknowledged: " + json.dumps(result))
        if not result["live_publication_received"] or not orderbook_shape_ok:
            raise RuntimeError("No valid live orderbook publication came through the relay: " + json.dumps(result))
        return result


def main() -> None:
    proxies = [
        item.strip()
        for item in os.environ.get("RAMZINEX_WS_HTTP_PROXIES", "").split(",")
        if item.strip()
    ]
    if not proxies:
        raise SystemExit("No currently verified Iran/Ramzinex HTTP proxy route was found; refusing direct fallback.")

    proxy = proxies[0]
    port = reserve_port()
    env = os.environ.copy()
    env["RAMZINEX_UPSTREAM_PROXY"] = proxy
    env["RAMZINEX_RELAY_TOKEN"] = TOKEN

    server = subprocess.Popen(
        [
            sys.executable, "-m", "uvicorn", "relay_app:app",
            "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning",
        ],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        health_url = f"http://127.0.0.1:{port}/health"
        ready = False
        for _ in range(80):
            if server.poll() is not None:
                raise RuntimeError("Local relay process exited before becoming healthy")
            try:
                with urllib.request.urlopen(health_url, timeout=1) as response:
                    health = json.loads(response.read().decode("utf-8"))
                    ready = response.status == 200 and health.get("upstream_proxy_configured") is True
                    if ready:
                        break
            except Exception:
                time.sleep(0.25)
        if not ready:
            raise TimeoutError("Local Ramzinex relay did not become healthy")

        result = asyncio.run(run_smoke(f"ws://127.0.0.1:{port}/ws"))
        print(json.dumps({
            "test": "live Ramzinex WebSocket through the new Python relay",
            "upstream_route": "verified-Iran-Ramzinex-proxy",
            **result,
        }, ensure_ascii=False, indent=2))
    finally:
        server.terminate()
        try:
            server.wait(timeout=8)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=4)


if __name__ == "__main__":
    main()
