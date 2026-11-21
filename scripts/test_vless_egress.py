import asyncio
import uuid

from vless_egress import _resolve_public_server_ip, parse_vless_source, parse_vless_uri


REALITY = (
    f"vless://{uuid.uuid4()}@8.8.8.8:443"
    "?encryption=none&security=reality&type=tcp&flow=xtls-rprx-vision"
    "&sni=www.example.com&fp=chrome&pbk=abcdefghijklmnopqrstuv"
    "&sid=abcd1234"
)
REALITY_XHTTP = (
    f"vless://{uuid.uuid4()}@xhttp.example.com:443"
    "?encryption=none&security=reality&type=xhttp&sni=xhttp.example.com"
    "&pbk=abcdefghijklmnopqrstuv&sid=abcd1234&path=%2Ffeed&mode=auto"
)
TLS_WS = (
    f"vless://{uuid.uuid4()}@edge.example.com:8443"
    "?encryption=none&security=tls&type=ws&sni=edge.example.com"
    "&host=edge.example.com&path=%2Fvless&fp=chrome"
)


def main():
    reality = parse_vless_uri(REALITY)
    assert reality is not None
    assert reality["security"] == "reality"
    assert reality["network"] == "raw"
    assert reality["config"]["outbounds"][0]["protocol"] == "vless"
    assert reality["config"]["inbounds"][0]["listen"] == "127.0.0.1"
    assert reality["config"]["outbounds"][0]["streamSettings"]["method"] == "raw"
    assert reality["config"]["outbounds"][0]["streamSettings"]["realitySettings"]["password"]

    ws = parse_vless_uri(TLS_WS)
    assert ws is not None
    assert ws["network"] == "ws"
    assert ws["config"]["outbounds"][0]["streamSettings"]["method"] == "websocket"
    assert ws["config"]["outbounds"][0]["streamSettings"]["wsSettings"]["path"] == "/vless"
    assert ws["config"]["outbounds"][0]["streamSettings"]["tlsSettings"]["allowInsecure"] is False

    xhttp = parse_vless_uri(REALITY_XHTTP)
    assert xhttp is not None
    assert xhttp["network"] == "xhttp"
    assert xhttp["config"]["outbounds"][0]["streamSettings"]["method"] == "xhttp"
    assert xhttp["config"]["outbounds"][0]["streamSettings"]["xhttpSettings"]["path"] == "/feed"
    assert xhttp["config"]["outbounds"][0]["streamSettings"]["xhttpSettings"]["mode"] == "auto"

    # The manager deliberately rejects unencrypted and unsupported nodes.
    assert parse_vless_uri(f"vless://{uuid.uuid4()}@example.com:80?security=none&type=ws") is None
    assert parse_vless_uri(f"vless://not-a-uuid@example.com:443?security=tls&sni=example.com&type=tcp") is None
    assert parse_vless_uri(f"vless://{uuid.uuid4()}@example.com:443?security=none&sni=example.com&type=xhttp") is None
    assert parse_vless_uri(f"vless://{uuid.uuid4()}@example.com:443?security=tls&sni=example.com&type=unknown") is None

    assert parse_vless_uri(f"vless://{uuid.uuid4()}@127.0.0.1:443?security=tls&sni=example.com&type=tcp") is None
    assert parse_vless_uri(f"vless://{uuid.uuid4()}@169.254.169.254:443?security=tls&sni=example.com&type=tcp") is None

    async def check_ip_pinning():
        assert await _resolve_public_server_ip("8.8.8.8", 443) == "8.8.8.8"
        assert await _resolve_public_server_ip("127.0.0.1", 443) is None
        assert await _resolve_public_server_ip("169.254.169.254", 443) is None

    asyncio.run(check_ip_pinning())

    # Failed public nodes are skipped during the cooldown so repeated refreshes
    # advance to different source entries instead of retrying the same dead node.
    from vless_egress import VlessEgressManager

    async def check_failure_cooldown():
        test_manager = VlessEgressManager()
        reality_key = reality["key"]

        class FakeResponse:
            def __init__(self, text):
                self.text = text

            def raise_for_status(self):
                return None

        class FakeClient:
            async def get(self, url, timeout=None):
                return FakeResponse(REALITY + "\n" + TLS_WS)

        await test_manager._remember_failure(reality_key)
        available = await test_manager.fetch_candidates(FakeClient(), limit=5)
        assert all(item["key"] != reality_key for item in available)
        assert any(item["network"] == "ws" for item in available)

    asyncio.run(check_failure_cooldown())

    rows = parse_vless_source(REALITY + "\n" + REALITY + "\n" + TLS_WS, limit=5)
    assert len(rows) == 2, len(rows)

    print("VLESS parser, TLS/REALITY safety gates, and deduplication passed")


if __name__ == "__main__":
    main()
