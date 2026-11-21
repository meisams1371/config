import uuid

from vless_egress import parse_vless_source, parse_vless_uri


REALITY = (
    f"vless://{uuid.uuid4()}@203.0.113.10:443"
    "?encryption=none&security=reality&type=tcp&flow=xtls-rprx-vision"
    "&sni=www.example.com&fp=chrome&pbk=abcdefghijklmnopqrstuv"
    "&sid=abcd1234"
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
    assert reality["config"]["outbounds"][0]["streamSettings"]["realitySettings"]["publicKey"]

    ws = parse_vless_uri(TLS_WS)
    assert ws is not None
    assert ws["network"] == "ws"
    assert ws["config"]["outbounds"][0]["streamSettings"]["wsSettings"]["path"] == "/vless"
    assert ws["config"]["outbounds"][0]["streamSettings"]["tlsSettings"]["allowInsecure"] is False

    # The manager deliberately rejects unencrypted and unsupported nodes.
    assert parse_vless_uri(f"vless://{uuid.uuid4()}@example.com:80?security=none&type=ws") is None
    assert parse_vless_uri(f"vless://not-a-uuid@example.com:443?security=tls&sni=example.com&type=tcp") is None
    assert parse_vless_uri(f"vless://{uuid.uuid4()}@example.com:443?security=tls&sni=example.com&type=xhttp") is None

    rows = parse_vless_source(REALITY + "\n" + REALITY + "\n" + TLS_WS, limit=5)
    assert len(rows) == 2, len(rows)

    print("VLESS parser, TLS/REALITY safety gates, and deduplication passed")


if __name__ == "__main__":
    main()
