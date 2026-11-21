"""Managed Xray-backed VLESS egress routes for the Ramzinex read-only relay.

Only strictly parsed VLESS links with TLS or REALITY transport are eligible.
Every route must subsequently pass the relay's independent exit-IP, GeoIP,
Ramzinex REST, and Centrifuge WebSocket checks before entering the live pool.
Raw share links and UUIDs are never logged or exposed by health endpoints.
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import os
import platform
import shutil
import socket
import tempfile
import urllib.request
import uuid as uuidlib
import zipfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit


XRAY_VERSION = os.environ.get("X4G_XRAY_VERSION", "v26.11.9")
XRAY_RELEASE_BASE = f"https://github.com/XTLS/Xray-core/releases/download/{XRAY_VERSION}"
DEFAULT_SOURCE_URLS = (
    "https://raw.githubusercontent.com/mmbateni/iran-intranet-access/main/outputs/ir_exit_configs.txt",
    "https://raw.githubusercontent.com/mmbateni/iran-intranet-access/main/outputs/ir_reality_configs.txt",
)
MAX_SOURCE_CANDIDATES = max(1, min(24, int(os.environ.get("RAMZINEX_VLESS_SCAN_LIMIT", "12"))))
SOCKS_START_TIMEOUT = 10.0

# Official XTLS/Xray-core release checksums for the pinned release.
XRAY_ASSETS = {
    "x86_64": (
        "Xray-linux-64.zip",
        "b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82",
    ),
    "amd64": (
        "Xray-linux-64.zip",
        "b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82",
    ),
    "aarch64": (
        "Xray-linux-arm64-v8a.zip",
        "64ed6858982a7f5eb85d88b811089063bd4f17561f4c8f44e0f1dc8e6f6430be",
    ),
    "arm64": (
        "Xray-linux-arm64-v8a.zip",
        "64ed6858982a7f5eb85d88b811089063bd4f17561f4c8f44e0f1dc8e6f6430be",
    ),
}


@dataclass
class ManagedVlessRoute:
    key: str
    proxy_url: str
    server_host: str
    server_port: int
    process: asyncio.subprocess.Process
    work_dir: str

    def candidate(self) -> dict:
        return {
            "proxy": self.proxy_url,
            "ip": self.server_host,
            "port": self.server_port,
            "anonymity": "vless-ir-exit-candidate",
            "listed_city": "Iran-source-unverified",
            "vless_route": True,
            "vless_key": self.key,
        }


def _first(params: dict[str, list[str]], name: str, default: str = "") -> str:
    values = params.get(name)
    return str(values[0]) if values else default


def _valid_host(host: str) -> bool:
    if not host or len(host) > 253 or any(ch in host for ch in "\r\n\t /@"):
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        try:
            encoded = host.encode("idna").decode("ascii")
        except Exception:
            return False
        if len(encoded) > 253:
            return False
        return all(
            label and len(label) <= 63
            and label[0] != "-" and label[-1] != "-"
            and all(ch.isalnum() or ch == "-" for ch in label)
            for label in encoded.rstrip(".").split(".")
        )


def parse_vless_uri(uri: str) -> dict | None:
    """Convert a conservative VLESS share-link subset into an Xray outbound."""
    line = str(uri or "").strip()
    if not line.startswith("vless://") or len(line) > 4096:
        return None
    if any(ch in line for ch in ("\r", "\n", "{", "}", "<", ">")):
        return None

    try:
        parsed = urlsplit(line)
        client_uuid = unquote(parsed.username or "")
        host = parsed.hostname or ""
        port = parsed.port
        uuidlib.UUID(client_uuid)
        if not _valid_host(host) or port is None or not (1 <= port <= 65535):
            return None

        params = parse_qs(parsed.query, keep_blank_values=True)
        security = _first(params, "security").lower()
        if security not in ("tls", "reality"):
            return None
        encryption = _first(params, "encryption", "none").lower()
        if encryption not in ("", "none"):
            return None

        sni = _first(params, "sni") or _first(params, "serverName")
        if not sni or not _valid_host(sni):
            return None
        fingerprint = _first(params, "fp", "chrome").lower()
        if fingerprint not in ("chrome", "firefox", "safari", "ios", "android", "edge", "random", "randomized", "qq", "360"):
            fingerprint = "chrome"

        network = _first(params, "type", "tcp").lower()
        if network in ("tcp", "raw"):
            network = "raw"
        if network not in ("raw", "ws", "grpc", "httpupgrade"):
            # Unsupported transports are rejected rather than guessed.
            return None

        flow = _first(params, "flow")
        if flow and (flow != "xtls-rprx-vision" or network != "raw" or security != "reality"):
            return None

        user = {"id": client_uuid, "encryption": "none"}
        if flow:
            user["flow"] = flow

        stream: dict = {"network": network, "security": security}
        if security == "tls":
            alpn = [x.strip() for x in _first(params, "alpn").split(",") if x.strip()]
            tls = {"serverName": sni, "fingerprint": fingerprint, "allowInsecure": False}
            if alpn:
                tls["alpn"] = alpn[:4]
            stream["tlsSettings"] = tls
        else:
            public_key = _first(params, "pbk") or _first(params, "publicKey")
            short_id = _first(params, "sid")
            if not public_key or len(public_key) > 160 or len(short_id) > 32:
                return None
            stream["realitySettings"] = {
                "serverName": sni,
                "fingerprint": fingerprint,
                "publicKey": public_key,
                "shortId": short_id,
                "spiderX": _first(params, "spx", "/")[:256],
            }

        host_header = _first(params, "host")
        path = _first(params, "path", "/") or "/"
        if len(path) > 1024 or any(ch in path for ch in "\r\n"):
            return None

        if network == "ws":
            headers = {}
            if host_header:
                if len(host_header) > 253 or any(ch in host_header for ch in "\r\n"):
                    return None
                headers["Host"] = host_header
            stream["wsSettings"] = {"path": path, "headers": headers}
        elif network == "grpc":
            service_name = _first(params, "serviceName")
            authority = _first(params, "authority") or host_header
            grpc = {"serviceName": service_name[:512], "multiMode": _first(params, "mode") == "multi"}
            if authority:
                if len(authority) > 253 or any(ch in authority for ch in "\r\n"):
                    return None
                grpc["authority"] = authority
            stream["grpcSettings"] = grpc
        elif network == "httpupgrade":
            settings = {"path": path}
            if host_header:
                if len(host_header) > 253 or any(ch in host_header for ch in "\r\n"):
                    return None
                settings["host"] = host_header
            stream["httpupgradeSettings"] = settings

        config = {
            "log": {"loglevel": "none"},
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": 0,  # Replaced with an allocated local-only SOCKS port.
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
                "sniffing": {"enabled": False},
                "tag": "x4g-local-socks",
            }],
            "outbounds": [{
                "tag": "x4g-vless-out",
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": host,
                        "port": port,
                        "users": [user],
                    }]
                },
                "streamSettings": stream,
            }],
            "routing": {
                "domainStrategy": "AsIs",
                "rules": [{
                    "type": "field",
                    "inboundTag": ["x4g-local-socks"],
                    "outboundTag": "x4g-vless-out",
                }],
            },
        }

        return {
            "key": hashlib.sha256(line.encode("utf-8")).hexdigest()[:24],
            "uri": line,
            "host": host,
            "port": int(port),
            "config": config,
            "security": security,
            "network": network,
        }
    except Exception:
        return None


def parse_vless_source(contents: str, limit: int = MAX_SOURCE_CANDIDATES) -> list[dict]:
    rows: list[dict] = []
    seen: set[str] = set()
    for line in str(contents or "").splitlines():
        candidate = parse_vless_uri(line.strip())
        if not candidate or candidate["key"] in seen:
            continue
        seen.add(candidate["key"])
        rows.append(candidate)
        if len(rows) >= max(1, min(64, int(limit))):
            break
    return rows


def _xray_binary() -> str | None:
    custom = os.environ.get("X4G_XRAY_BINARY", "").strip()
    if custom:
        return os.path.abspath(custom) if os.path.isfile(custom) else None
    if os.name != "posix" or platform.system().lower() != "linux":
        return None

    arch = platform.machine().lower()
    asset = XRAY_ASSETS.get(arch)
    if not asset:
        return None
    filename, expected_sha256 = asset

    cache_root = Path(os.environ.get("X4G_XRAY_CACHE_DIR", "/tmp/x4g-xray"))
    target_dir = cache_root / XRAY_VERSION
    binary_path = target_dir / "xray"
    if binary_path.is_file():
        return str(binary_path)

    target_dir.mkdir(parents=True, exist_ok=True)
    download_url = f"{XRAY_RELEASE_BASE}/{filename}"
    request = urllib.request.Request(
        download_url,
        headers={"User-Agent": "X4G-Ramzinex-VLESS-Egress/1.0"},
    )
    with urllib.request.urlopen(request, timeout=45) as response:
        archive = response.read(40 * 1024 * 1024 + 1)
    if len(archive) > 40 * 1024 * 1024:
        raise RuntimeError("Xray release archive exceeded the size limit")
    actual = hashlib.sha256(archive).hexdigest()
    if actual.lower() != expected_sha256.lower():
        raise RuntimeError("Xray release SHA-256 verification failed")

    with tempfile.TemporaryDirectory(prefix="x4g-xray-extract-") as extract_dir:
        archive_path = Path(extract_dir) / filename
        archive_path.write_bytes(archive)
        with zipfile.ZipFile(archive_path) as bundle:
            info = next((item for item in bundle.infolist() if Path(item.filename).name == "xray"), None)
            if info is None:
                raise RuntimeError("Xray binary was not found in the verified release archive")
            binary_path.write_bytes(bundle.read(info))
    binary_path.chmod(0o755)
    return str(binary_path)


class VlessEgressManager:
    """Own short-lived Xray processes and their loopback-only SOCKS listeners."""

    def __init__(self) -> None:
        self._routes: dict[str, ManagedVlessRoute] = {}
        self._lock = asyncio.Lock()

    async def fetch_candidates(self, direct_client, limit: int = MAX_SOURCE_CANDIDATES) -> list[dict]:
        configured = os.environ.get("RAMZINEX_VLESS_SOURCE_URLS", "").strip()
        urls = [x.strip() for x in configured.split(";") if x.strip()] if configured else list(DEFAULT_SOURCE_URLS)
        parsed: list[dict] = []
        seen: set[str] = set()
        for url in urls[:4]:
            try:
                response = await direct_client.get(url, timeout=12.0)
                response.raise_for_status()
                for row in parse_vless_source(response.text, limit=limit):
                    if row["key"] not in seen:
                        seen.add(row["key"])
                        parsed.append(row)
                    if len(parsed) >= limit:
                        return parsed
            except Exception:
                continue
        return parsed

    async def active_candidates(self) -> list[dict]:
        async with self._lock:
            return [{**route.candidate(), "key": route.key} for route in self._routes.values()
                    if route.process.returncode is None]

    async def start(self, candidate: dict) -> ManagedVlessRoute | None:
        key = str(candidate.get("key") or "")
        async with self._lock:
            existing = self._routes.get(key)
            if existing and existing.process.returncode is None:
                return existing
            if existing:
                self._routes.pop(key, None)

        if not key or not candidate.get("config"):
            return None

        try:
            binary = await asyncio.to_thread(_xray_binary)
            if not binary:
                return None

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.bind(("127.0.0.1", 0))
                local_port = int(listener.getsockname()[1])

            work_dir = tempfile.mkdtemp(prefix="x4g-vless-")
            config = json.loads(json.dumps(candidate["config"]))
            config["inbounds"][0]["port"] = local_port
            config_path = os.path.join(work_dir, "config.json")
            with open(config_path, "w", encoding="utf-8") as handle:
                json.dump(config, handle, ensure_ascii=False)

            process = await asyncio.create_subprocess_exec(
                binary, "run", "-c", config_path,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            route = ManagedVlessRoute(
                key=key,
                proxy_url=f"socks5://127.0.0.1:{local_port}",
                server_host=str(candidate.get("host") or ""),
                server_port=int(candidate.get("port") or 0),
                process=process,
                work_dir=work_dir,
            )

            deadline = asyncio.get_running_loop().time() + SOCKS_START_TIMEOUT
            while asyncio.get_running_loop().time() < deadline:
                if process.returncode is not None:
                    raise RuntimeError("Xray process exited before SOCKS listener became ready")
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection("127.0.0.1", local_port),
                        timeout=0.5,
                    )
                    writer.close()
                    await writer.wait_closed()
                    break
                except Exception:
                    await asyncio.sleep(0.2)
            else:
                raise TimeoutError("Xray SOCKS listener did not start")

            async with self._lock:
                self._routes[key] = route
            return route
        except Exception:
            try:
                if "process" in locals() and process.returncode is None:
                    process.terminate()
                    await asyncio.wait_for(process.wait(), timeout=2)
            except Exception:
                try:
                    process.kill()
                    await process.wait()
                except Exception:
                    pass
            if "work_dir" in locals():
                shutil.rmtree(work_dir, ignore_errors=True)
            return None

    async def stop(self, proxy_url: str) -> None:
        async with self._lock:
            key = next((key for key, route in self._routes.items()
                        if route.proxy_url == proxy_url), None)
            route = self._routes.pop(key, None) if key else None
        if route:
            await self._stop_route(route)

    async def keep_only(self, proxy_urls: set[str]) -> None:
        async with self._lock:
            stale = [
                (key, route) for key, route in self._routes.items()
                if route.proxy_url not in proxy_urls
            ]
            for key, _ in stale:
                self._routes.pop(key, None)
        await asyncio.gather(*(self._stop_route(route) for _, route in stale),
                             return_exceptions=True)

    async def stop_all(self) -> None:
        async with self._lock:
            routes = list(self._routes.values())
            self._routes.clear()
        await asyncio.gather(*(self._stop_route(route) for route in routes),
                             return_exceptions=True)

    async def _stop_route(self, route: ManagedVlessRoute) -> None:
        process = route.process
        try:
            if process.returncode is None:
                process.terminate()
                await asyncio.wait_for(process.wait(), timeout=3)
        except Exception:
            try:
                process.kill()
                await asyncio.wait_for(process.wait(), timeout=2)
            except Exception:
                pass
        shutil.rmtree(route.work_dir, ignore_errors=True)


manager = VlessEgressManager()
