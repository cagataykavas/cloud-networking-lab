from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.runtime_reachability import (
    CommandResult,
    ConfigurationError,
    OperationalError,
    ReachabilityPolicy,
    audit_reachability,
    canonical_digest,
    main,
    strict_json_loads,
    topology_from_config,
)


def compose_config() -> dict[str, object]:
    return {
        "name": "network-reachability-audit",
        "services": {
            "proxy": {
                "ports": [{"target": 80, "published": "8080"}],
                "networks": {"edge": None, "private_app": None},
            },
            "backend_a": {
                "environment": {"INSTANCE_ID": "backend-a"},
                "networks": {"private_app": {"ipv4_address": "172.29.0.11"}},
            },
            "backend_b": {
                "environment": {"INSTANCE_ID": "backend-b"},
                "networks": {"private_app": {"ipv4_address": "172.29.0.12"}},
            },
        },
        "networks": {
            "edge": {
                "name": "network-reachability-audit_edge",
                "driver": "bridge",
                "ipam": {"config": [{"subnet": "172.28.0.0/24"}]},
            },
            "private_app": {
                "name": "network-reachability-audit_private_app",
                "driver": "bridge",
                "internal": True,
                "ipam": {"config": [{"subnet": "172.29.0.0/24"}]},
            },
        },
    }


class FakeRunner:
    def __init__(self, probe_returncodes: list[int] | None = None) -> None:
        self.commands: list[list[str]] = []
        self.probe_returncodes = iter(probe_returncodes or [0, 0, 0, 0, 0])

    def __call__(self, command: list[str], timeout: float) -> CommandResult:
        assert timeout > 0
        self.commands.append(list(command))
        if command[-3:] == ["config", "--format", "json"]:
            return CommandResult(0, json.dumps(compose_config()), "")
        if command[:2] == ["docker", "pull"]:
            return CommandResult(0, "pulled", "")
        if command[1] == "compose" and "up" in command:
            return CommandResult(0, "started", "")
        if command[1] == "compose" and "down" in command:
            return CommandResult(0, "removed", "")
        if command[1] == "run":
            return CommandResult(next(self.probe_returncodes), "", "")
        raise AssertionError(command)


def test_canonical_digest_is_order_independent_and_finite() -> None:
    assert canonical_digest({"b": 2, "a": 1}) == canonical_digest({"a": 1, "b": 2})
    with pytest.raises(ValueError):
        canonical_digest({"bad": float("nan")})


def test_strict_json_rejects_duplicates_non_finite_and_large_input() -> None:
    with pytest.raises(ConfigurationError, match="duplicate"):
        strict_json_loads('{"services": {}, "services": {}}')
    with pytest.raises(ConfigurationError, match="non-finite"):
        strict_json_loads('{"bad": NaN}')
    with pytest.raises(ConfigurationError, match="byte budget"):
        strict_json_loads('"' + "x" * (256 * 1024) + '"')


def test_policy_rejects_unsafe_project_and_probe_configuration() -> None:
    with pytest.raises(ConfigurationError, match="project_name"):
        ReachabilityPolicy(project_name="../../shared").validate()
    with pytest.raises(ConfigurationError, match="backend_services"):
        ReachabilityPolicy(backend_services=("backend_a", "backend_a")).validate()
    with pytest.raises(ConfigurationError, match="probe_image"):
        ReachabilityPolicy(probe_image="python@sha256:unreviewed").validate()
    ReachabilityPolicy(probe_image="python@sha256:" + "a" * 64).validate()


def test_topology_requires_dual_homed_proxy_and_private_backends() -> None:
    policy = ReachabilityPolicy()
    topology = topology_from_config(compose_config(), policy)
    assert topology.edge_network_name == "network-reachability-audit_edge"
    assert topology.backend_endpoints == (
        ("backend_a", "172.29.0.11", "backend-a"),
        ("backend_b", "172.29.0.12", "backend-b"),
    )

    bad = compose_config()
    bad["services"]["backend_a"]["networks"]["edge"] = None  # type: ignore[index]
    with pytest.raises(ConfigurationError, match="only the private"):
        topology_from_config(bad, policy)

    published = compose_config()
    published["services"]["backend_b"]["ports"] = ["8000:8000"]  # type: ignore[index]
    with pytest.raises(ConfigurationError, match="must not publish"):
        topology_from_config(published, policy)


def test_accepted_audit_hardens_probe_and_cleans_up() -> None:
    runner = FakeRunner()
    report = audit_reachability(ReachabilityPolicy(), runner=runner)

    assert report["accepted"] is True
    assert len(report["observations"]) == 5
    assert len(report["evidence_sha256"]) == 64
    probe_commands = [command for command in runner.commands if command[1] == "run"]
    assert all("--read-only" in command for command in probe_commands)
    assert all("--cap-drop=ALL" in command for command in probe_commands)
    assert all("--network" in command for command in probe_commands)
    assert "down" in runner.commands[-1]


@pytest.mark.parametrize(
    ("probe_returncodes", "reason"),
    [
        ([20, 0, 0, 0, 0], "PROXY_PATH_UNAVAILABLE"),
        ([0, 20, 0, 0, 0], "BACKEND_DNS_REACHABLE_FROM_EDGE"),
        ([0, 0, 20, 0, 0], "BACKEND_IP_REACHABLE_FROM_EDGE"),
    ],
)
def test_policy_breaches_are_reported_and_cleanup_still_runs(
    probe_returncodes: list[int], reason: str
) -> None:
    runner = FakeRunner(probe_returncodes)
    report = audit_reachability(ReachabilityPolicy(), runner=runner)
    assert report["accepted"] is False
    assert reason in {item["reason"] for item in report["observations"]}
    assert "down" in runner.commands[-1]


def test_unexpected_probe_failure_is_operational_and_cleanup_runs() -> None:
    runner = FakeRunner([0, 21])
    with pytest.raises(OperationalError, match="unexpected exit code"):
        audit_reachability(ReachabilityPolicy(), runner=runner)
    assert "down" in runner.commands[-1]


def test_failed_compose_start_still_cleans_up() -> None:
    runner = FakeRunner()
    original = runner.__call__

    def fail_up(command: list[str], timeout: float) -> CommandResult:
        if command[1] == "compose" and "up" in command:
            runner.commands.append(list(command))
            return CommandResult(1, "", "daemon failure")
        return original(command, timeout)

    with pytest.raises(OperationalError, match="compose up"):
        audit_reachability(ReachabilityPolicy(), runner=fail_up)
    assert "down" in runner.commands[-1]


def test_cli_writes_bounded_failure_without_exception_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "report.json"

    def fail(_: ReachabilityPolicy) -> dict[str, object]:
        raise OperationalError("sensitive daemon detail")

    monkeypatch.setattr("tools.runtime_reachability.audit_reachability", fail)
    assert main(["--output", str(output)]) == 3
    report = json.loads(output.read_text())
    assert report == {
        "accepted": False,
        "error_code": "OPERATIONAL_ERROR",
        "schema_version": 1,
    }
    assert "sensitive" not in capsys.readouterr().out
