from __future__ import annotations

import copy
import json

import pytest

from tools.topology_audit import (
    ArtifactError,
    TopologyPolicy,
    audit_topology,
    load_compose_json,
    main,
)


@pytest.fixture
def policy() -> TopologyPolicy:
    return TopologyPolicy(
        edge_network="edge",
        private_network="private_app",
        gateway_service="proxy",
        backend_services=("backend_a", "backend_b"),
    )


@pytest.fixture
def topology() -> dict[str, object]:
    return {
        "name": "cloud-networking-lab",
        "services": {
            "proxy": {
                "networks": {"edge": None, "private_app": None},
                "ports": [
                    {"mode": "ingress", "target": 80, "published": "8080", "protocol": "tcp"}
                ],
                "volumes": [{"source": "/machine-specific/checkout/nginx.conf"}],
            },
            "backend_a": {
                "networks": {"private_app": {"ipv4_address": "172.29.0.11"}},
            },
            "backend_b": {
                "networks": {"private_app": {"ipv4_address": "172.29.0.12"}},
            },
        },
        "networks": {
            "edge": {
                "driver": "bridge",
                "ipam": {"config": [{"subnet": "172.28.0.0/24"}]},
            },
            "private_app": {
                "driver": "bridge",
                "internal": True,
                "ipam": {"config": [{"subnet": "172.29.0.0/24"}]},
            },
        },
    }


def codes(report: object) -> set[str]:
    return {item.code for item in report.violations}


def test_accepts_expected_edge_to_private_topology(
    topology: dict[str, object], policy: TopologyPolicy
) -> None:
    report = audit_topology(topology, policy)

    assert report.accepted
    assert report.service_count == 3
    assert report.network_count == 2
    assert report.attachment_count == 4
    assert len(report.topology_sha256) == 64


def test_digest_ignores_checkout_path_and_json_key_order(
    topology: dict[str, object], policy: TopologyPolicy
) -> None:
    first = audit_topology(topology, policy)
    changed = json.loads(json.dumps(topology, sort_keys=True))
    changed["services"]["proxy"]["volumes"][0]["source"] = "/different/runner/nginx.conf"

    second = audit_topology(changed, policy)

    assert first.topology_sha256 == second.topology_sha256
    assert first.policy_sha256 == second.policy_sha256


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (
            lambda value: value["services"]["backend_a"].update({"ports": [{"target": 8000}]}),
            "backend_publishes_host_port",
        ),
        (
            lambda value: value["services"]["backend_a"]["networks"].update({"edge": None}),
            "backend_attached_to_edge",
        ),
        (
            lambda value: value["services"]["proxy"]["networks"].pop("private_app"),
            "gateway_missing_network",
        ),
        (
            lambda value: value["networks"]["private_app"].update({"internal": False}),
            "private_network_not_internal",
        ),
        (
            lambda value: value["networks"]["edge"].update({"driver": "host"}),
            "unsupported_network_driver",
        ),
        (
            lambda value: value["services"]["backend_a"].update({"network_mode": "host"}),
            "host_network_mode",
        ),
        (
            lambda value: value["services"]["backend_a"].update({"privileged": True}),
            "privileged_service",
        ),
        (
            lambda value: value["services"]["backend_a"].update({"cap_add": ["NET_ADMIN"]}),
            "dangerous_network_capability",
        ),
    ],
)
def test_rejects_network_boundary_bypasses(
    topology: dict[str, object],
    policy: TopologyPolicy,
    mutation: object,
    expected: str,
) -> None:
    mutation(topology)

    report = audit_topology(topology, policy)

    assert not report.accepted
    assert expected in codes(report)


def test_rejects_overlapping_networks(topology: dict[str, object], policy: TopologyPolicy) -> None:
    topology["networks"]["private_app"]["ipam"]["config"][0]["subnet"] = "172.28.0.0/25"

    report = audit_topology(topology, policy)

    assert "overlapping_subnets" in codes(report)


def test_rejects_static_address_outside_declared_subnet(
    topology: dict[str, object], policy: TopologyPolicy
) -> None:
    topology["services"]["backend_a"]["networks"]["private_app"]["ipv4_address"] = "10.0.0.2"

    report = audit_topology(topology, policy)

    assert "static_address_outside_subnet" in codes(report)


def test_rejects_duplicate_static_addresses(
    topology: dict[str, object], policy: TopologyPolicy
) -> None:
    topology["services"]["backend_b"]["networks"]["private_app"]["ipv4_address"] = "172.29.0.11"

    report = audit_topology(topology, policy)

    assert "duplicate_static_address" in codes(report)


def test_rejects_unmanaged_service_on_audited_network(
    topology: dict[str, object], policy: TopologyPolicy
) -> None:
    topology["services"]["debug_shell"] = {"networks": {"private_app": None}}

    report = audit_topology(topology, policy)

    assert "unmanaged_service" in codes(report)


def test_rejects_unexpected_gateway_publication(
    topology: dict[str, object], policy: TopologyPolicy
) -> None:
    topology["services"]["proxy"]["ports"][0]["target"] = 22

    report = audit_topology(topology, policy)

    assert "unexpected_gateway_publication" in codes(report)


@pytest.mark.parametrize(
    "payload",
    [
        b'{"services":{},"services":{},"networks":{}}',
        b'{"services":{"x":{"value":NaN}},"networks":{}}',
        b"[]",
        b"not-json",
    ],
)
def test_loader_fails_closed_on_malformed_json(payload: bytes) -> None:
    with pytest.raises(ArtifactError):
        load_compose_json(payload)


def test_policy_rejects_ambiguous_roles() -> None:
    with pytest.raises(ValueError, match="gateway cannot"):
        TopologyPolicy("edge", "private", "proxy", ("proxy",))


def test_cli_distinguishes_policy_rejection_from_malformed_input(
    tmp_path: object,
    topology: dict[str, object],
    capsys: pytest.CaptureFixture[str],
) -> None:
    rejected = copy.deepcopy(topology)
    rejected["networks"]["private_app"]["internal"] = False
    rejected_path = tmp_path / "rejected.json"
    rejected_path.write_text(json.dumps(rejected))
    malformed_path = tmp_path / "malformed.json"
    malformed_path.write_text("{")
    args = ["--backend-service", "backend_a", "--backend-service", "backend_b"]

    assert main([str(rejected_path), *args]) == 2
    assert json.loads(capsys.readouterr().out)["accepted"] is False
    assert main([str(malformed_path), *args]) == 3
    assert json.loads(capsys.readouterr().out)["error"] == "malformed_artifact"
