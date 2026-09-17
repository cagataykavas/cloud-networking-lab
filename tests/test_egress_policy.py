from __future__ import annotations

from tools.egress_policy import EgressPolicy, evaluate_destination

POLICY = EgressPolicy(allowed_hosts=("api.example.com", "*.trusted.example"))


def test_allows_https_allowlisted_host_with_global_dns_answers() -> None:
    decision = evaluate_destination(
        "https://api.example.com/v1/models",
        ["8.8.8.8", "2001:4860:4860::8888"],
        POLICY,
    )

    assert decision.allowed
    assert decision.reasons == ()
    assert decision.port == 443


def test_blocks_mixed_public_private_dns_to_prevent_rebinding() -> None:
    decision = evaluate_destination(
        "https://api.example.com/data",
        ["8.8.8.8", "10.20.30.40"],
        POLICY,
    )

    assert not decision.allowed
    assert "non_global_address_blocked:10.20.30.40" in decision.reasons


def test_wildcard_matches_subdomain_but_not_apex_or_lookalike() -> None:
    subdomain = evaluate_destination("https://ml.trusted.example", ["8.8.4.4"], POLICY)
    apex = evaluate_destination("https://trusted.example", ["8.8.4.4"], POLICY)
    lookalike = evaluate_destination("https://eviltrusted.example", ["8.8.4.4"], POLICY)

    assert subdomain.allowed
    assert not apex.allowed
    assert not lookalike.allowed


def test_blocks_credentials_scheme_and_unapproved_port() -> None:
    decision = evaluate_destination(
        "http://user:secret@api.example.com:8080/data",
        ["8.8.8.8"],
        POLICY,
    )

    assert not decision.allowed
    assert "scheme_not_allowed:http" in decision.reasons
    assert "embedded_credentials_not_allowed" in decision.reasons
    assert "port_not_allowed:8080" in decision.reasons


def test_private_exception_never_overrides_cloud_metadata_block() -> None:
    policy = EgressPolicy(
        allowed_hosts=("metadata.internal",),
        allowed_private_cidrs=("169.254.0.0/16",),
    )
    decision = evaluate_destination(
        "https://metadata.internal",
        ["169.254.169.254"],
        policy,
    )

    assert not decision.allowed
    assert "metadata_endpoint_blocked:169.254.169.254" in decision.reasons


def test_explicit_private_service_cidr_can_be_allowed() -> None:
    policy = EgressPolicy(
        allowed_hosts=("model.internal",),
        allowed_private_cidrs=("10.42.0.0/16",),
    )
    decision = evaluate_destination("https://model.internal", ["10.42.3.8"], policy)

    assert decision.allowed


def test_ip_literal_is_validated_even_without_dns_answers() -> None:
    policy = EgressPolicy(allowed_hosts=("127.0.0.1",))
    decision = evaluate_destination("https://127.0.0.1/health", [], policy)

    assert not decision.allowed
    assert "non_global_address_blocked:127.0.0.1" in decision.reasons
