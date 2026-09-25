from __future__ import annotations

from ipaddress import ip_address

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from app import backend
from app.proxy_trust import (
    ProxyEvidenceError,
    TrustedProxyPolicy,
    resolve_client_identity,
)

POLICY = TrustedProxyPolicy(trusted_proxy_cidrs=("10.0.0.0/24", "2001:db8:1::/64"))


def test_direct_peer_is_authoritative_without_a_trusted_proxy() -> None:
    identity = resolve_client_identity("198.51.100.9", None, POLICY)

    assert identity.client_ip == "198.51.100.9"
    assert identity.source == "direct"
    assert identity.status == "DIRECT_PEER"


def test_untrusted_peer_cannot_spoof_forwarded_identity() -> None:
    identity = resolve_client_identity(
        "198.51.100.9",
        "203.0.113.44, 10.0.0.8",
        POLICY,
    )

    assert identity.client_ip == "198.51.100.9"
    assert identity.status == "UNTRUSTED_PEER_IGNORED_FORWARDED"
    assert identity.forwarded_hop_count == 0


def test_walks_right_to_left_and_ignores_attacker_prepended_hop() -> None:
    identity = resolve_client_identity(
        "10.0.0.8",
        "192.0.2.66, 203.0.113.20, 10.0.0.7",
        POLICY,
    )

    assert identity.client_ip == "203.0.113.20"
    assert identity.source == "forwarded"
    assert identity.forwarded_hop_count == 3
    assert identity.trusted_proxy_hop_count == 2


def test_canonicalizes_ipv6_client_and_proxy_addresses() -> None:
    identity = resolve_client_identity(
        "2001:db8:1:0:0:0:0:9",
        "2001:0db8:2:0:0:0:0:44",
        POLICY,
    )

    assert identity.client_ip == "2001:db8:2::44"
    assert identity.peer_ip == "2001:db8:1::9"


@pytest.mark.parametrize(
    ("header", "code"),
    [
        ("", "FORWARDED_HOP_EMPTY"),
        ("203.0.113.1,,203.0.113.2", "FORWARDED_HOP_EMPTY"),
        ("unknown", "FORWARDED_HOP_INVALID"),
        ("203.0.113.1:443", "FORWARDED_HOP_INVALID"),
        ("fe80::1%eth0", "FORWARDED_HOP_INVALID"),
    ],
)
def test_trusted_proxy_chain_rejects_ambiguous_hops(header: str, code: str) -> None:
    with pytest.raises(ProxyEvidenceError) as raised:
        resolve_client_identity("10.0.0.8", header, POLICY)

    assert raised.value.code == code


def test_enforces_header_and_hop_budgets() -> None:
    byte_policy = TrustedProxyPolicy(
        trusted_proxy_cidrs=("10.0.0.0/24",),
        max_header_bytes=64,
    )
    with pytest.raises(ProxyEvidenceError) as raised:
        resolve_client_identity("10.0.0.8", "1" * 65, byte_policy)
    assert raised.value.code == "FORWARDED_HEADER_TOO_LARGE"

    hop_policy = TrustedProxyPolicy(
        trusted_proxy_cidrs=("10.0.0.0/24",),
        max_forwarded_hops=2,
    )
    with pytest.raises(ProxyEvidenceError) as raised:
        resolve_client_identity("10.0.0.8", "192.0.2.1,192.0.2.2,192.0.2.3", hop_policy)
    assert raised.value.code == "FORWARDED_HOP_LIMIT_EXCEEDED"


def test_trusted_proxy_requires_a_chain_with_an_untrusted_client() -> None:
    with pytest.raises(ProxyEvidenceError) as missing:
        resolve_client_identity("10.0.0.8", None, POLICY)
    assert missing.value.code == "FORWARDED_CHAIN_MISSING"

    with pytest.raises(ProxyEvidenceError) as all_trusted:
        resolve_client_identity("10.0.0.8", "10.0.0.7", POLICY)
    assert all_trusted.value.code == "NO_UNTRUSTED_CLIENT_HOP"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"trusted_proxy_cidrs": ("0.0.0.0/0",)},
        {"trusted_proxy_cidrs": ("10.0.0.1/24",)},
        {"trusted_proxy_cidrs": ("10.0.0.0/24", "10.0.0.0/24")},
        {"trusted_proxy_cidrs": (" bad",)},
        {"trusted_proxy_cidrs": ["10.0.0.0/24"]},
        {"max_forwarded_hops": True},
        {"max_forwarded_hops": 65},
        {"max_header_bytes": 63},
    ],
)
def test_policy_rejects_unsafe_or_malformed_configuration(kwargs: dict) -> None:
    with pytest.raises(ValueError):
        TrustedProxyPolicy(**kwargs)


def _request(peer: str, forwarded_for: str | None) -> Request:
    headers = [] if forwarded_for is None else [(b"x-forwarded-for", forwarded_for.encode())]
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/whoami",
            "headers": headers,
            "client": (peer, 12345),
            "server": ("testserver", 80),
            "scheme": "http",
            "query_string": b"",
        }
    )


def test_whoami_reports_derived_identity_without_echoing_raw_chain(monkeypatch) -> None:
    monkeypatch.setattr(
        backend,
        "TRUSTED_PROXY_POLICY",
        TrustedProxyPolicy(trusted_proxy_cidrs=("172.29.0.0/24",)),
    )
    raw_chain = "192.0.2.10, 198.51.100.22"
    payload = backend.whoami(_request("172.29.0.4", raw_chain), x_request_id="req-1")

    assert payload["client_ip"] == "198.51.100.22"
    assert payload["client_ip_source"] == "forwarded"
    assert payload["proxy_evidence_status"] == "TRUSTED_PROXY_CHAIN"
    assert payload["forwarded_hop_count"] == 2
    assert raw_chain not in str(payload)


def test_whoami_fails_closed_without_leaking_malformed_header(monkeypatch) -> None:
    monkeypatch.setattr(
        backend,
        "TRUSTED_PROXY_POLICY",
        TrustedProxyPolicy(trusted_proxy_cidrs=("172.29.0.0/24",)),
    )
    secret = "not-an-ip-secret"
    payload = backend.whoami(_request("172.29.0.4", secret), x_request_id=None)

    assert payload["client_ip"] is None
    assert payload["client_ip_source"] == "unattributed"
    assert payload["proxy_evidence_status"] == "FORWARDED_HOP_INVALID"
    assert secret not in str(payload)


def test_http_endpoint_ignores_spoofed_chain_from_direct_client(monkeypatch) -> None:
    monkeypatch.setattr(
        backend,
        "TRUSTED_PROXY_POLICY",
        TrustedProxyPolicy(trusted_proxy_cidrs=("172.29.0.0/24",)),
    )
    client = TestClient(backend.app, client=("198.51.100.40", 41000))

    response = client.get("/whoami", headers={"X-Forwarded-For": "203.0.113.99"})

    assert response.status_code == 200
    payload = response.json()
    assert payload["client_ip"] == "198.51.100.40"
    assert payload["proxy_evidence_status"] == "UNTRUSTED_PEER_IGNORED_FORWARDED"


def test_http_endpoint_accepts_chain_only_from_configured_proxy(monkeypatch) -> None:
    monkeypatch.setattr(
        backend,
        "TRUSTED_PROXY_POLICY",
        TrustedProxyPolicy(trusted_proxy_cidrs=("172.29.0.0/24",)),
    )
    client = TestClient(backend.app, client=("172.29.0.4", 41000))

    response = client.get(
        "/whoami",
        headers={"X-Forwarded-For": "192.0.2.3, 198.51.100.40"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["client_ip"] == "198.51.100.40"
    assert payload["trusted_proxy_hop_count"] == 1
    assert payload["forwarded_hop_count"] == 2


def test_policy_membership_handles_both_address_families() -> None:
    assert POLICY.trusts(ip_address("10.0.0.8"))
    assert POLICY.trusts(ip_address("2001:db8:1::8"))
    assert not POLICY.trusts(ip_address("10.0.1.8"))


def test_environment_policy_rejects_empty_entries(monkeypatch) -> None:
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS", "172.29.0.0/24,")

    with pytest.raises(ValueError, match="empty entry"):
        backend._proxy_policy_from_environment()
