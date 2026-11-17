import pytest
from fastapi.testclient import TestClient

import app.backend as backend
from app.client_identity import (
    parse_trusted_proxy_cidrs,
    resolve_client_identity,
)
from app.backend import app
from tools.network_probe import probe


def test_backend_health() -> None:
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["instance_id"]


def test_echo_round_trip() -> None:
    client = TestClient(app)
    response = client.post("/echo", json={"message": "hello-network"})
    assert response.status_code == 200
    assert response.json()["message"] == "hello-network"


def test_probe_rejects_invalid_scheme() -> None:
    try:
        probe("ftp://example.com")
    except ValueError as exc:
        assert "http" in str(exc)
    else:
        raise AssertionError("invalid URL scheme should fail")


def test_untrusted_peer_cannot_spoof_forwarded_client() -> None:
    identity = resolve_client_identity(
        "192.0.2.10",
        "198.51.100.99",
        parse_trusted_proxy_cidrs("172.29.0.10/32"),
    )

    assert identity.client_ip == "192.0.2.10"
    assert identity.source == "peer"
    assert not identity.forwarded_header_accepted


def test_rightmost_untrusted_hop_defeats_leftmost_spoof() -> None:
    identity = resolve_client_identity(
        "172.29.0.10",
        "198.51.100.99, 203.0.113.7",
        parse_trusted_proxy_cidrs("172.29.0.10/32"),
    )

    assert identity.client_ip == "203.0.113.7"
    assert identity.source == "forwarded"
    assert identity.forwarded_header_accepted


def test_trusted_proxy_chain_is_walked_right_to_left() -> None:
    identity = resolve_client_identity(
        "172.29.0.10",
        "203.0.113.8, 10.0.0.5",
        parse_trusted_proxy_cidrs("172.29.0.10/32,10.0.0.0/24"),
    )

    assert identity.client_ip == "203.0.113.8"
    assert identity.forwarded_header_accepted


@pytest.mark.parametrize(
    "header",
    ["not-an-ip", ",", "x" * 2_049, ", ".join(["192.0.2.1"] * 33)],
)
def test_malformed_forwarded_chain_fails_closed(header: str) -> None:
    identity = resolve_client_identity(
        "172.29.0.10",
        header,
        parse_trusted_proxy_cidrs("172.29.0.10/32"),
    )

    assert identity.client_ip == "172.29.0.10"
    assert identity.source == "peer"
    assert not identity.forwarded_header_accepted
    assert identity.error


def test_invalid_trusted_proxy_configuration_is_rejected() -> None:
    with pytest.raises(ValueError, match="trusted proxy CIDR"):
        parse_trusted_proxy_cidrs("172.29.0.10/24")


def test_whoami_reports_resolved_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        backend,
        "TRUSTED_PROXY_NETWORKS",
        parse_trusted_proxy_cidrs("172.29.0.10/32"),
    )
    client = TestClient(app, client=("172.29.0.10", 50000))

    response = client.get(
        "/whoami",
        headers={"X-Forwarded-For": "198.51.100.99, 203.0.113.7"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["client_host"] == "172.29.0.10"
    assert payload["peer_ip"] == "172.29.0.10"
    assert payload["client_ip"] == "203.0.113.7"
    assert payload["client_ip_source"] == "forwarded"
    assert payload["forwarded_header_accepted"] is True
