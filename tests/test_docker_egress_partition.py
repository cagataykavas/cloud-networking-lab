from __future__ import annotations

import subprocess

import pytest

from tools.docker_egress_partition import (
    RULE_COMMENT,
    SERVICE,
    DockerEgressPartition,
    run_command,
)


PEERS = ("172.30.0.11", "172.30.0.21", "172.30.0.22", "172.30.0.23")


class RecordingRunner:
    def __init__(self, *, fail_at: int | None = None) -> None:
        self.commands: list[tuple[list[str], float]] = []
        self.fail_at = fail_at

    def __call__(self, command: list[str], timeout_seconds: float) -> None:
        self.commands.append((command, timeout_seconds))
        if self.fail_at == len(self.commands):
            raise RuntimeError("injected command failure")


def test_installs_verifies_and_removes_exact_peer_rules() -> None:
    runner = RecordingRunner()
    partition = DockerEgressPartition(PEERS, timeout_seconds=7, runner=runner)

    partition.isolate()
    assert partition.active
    partition.heal()
    assert not partition.active
    partition.heal()

    commands = [command for command, _ in runner.commands]
    assert len(commands) == 12
    assert all(
        command[:7] == ["docker", "compose", "exec", "-T", "--user", "0", SERVICE]
        for command in commands
    )
    assert [command[10] for command in commands[:4]] == ["-I"] * 4
    assert [command[10] for command in commands[4:8]] == ["-C"] * 4
    assert [command[10] for command in commands[8:]] == ["-D"] * 4
    assert all(RULE_COMMENT in command for command in commands)
    assert all(timeout == 7 for _, timeout in runner.commands)
    assert {command[command.index("-d") + 1] for command in commands} == set(PEERS)


def test_rolls_back_partial_installation_on_failure() -> None:
    runner = RecordingRunner(fail_at=3)
    partition = DockerEgressPartition(PEERS, runner=runner)

    with pytest.raises(RuntimeError, match="injected"):
        partition.isolate()

    assert not partition.active
    actions = [command[10] for command, _ in runner.commands]
    assert actions == ["-I", "-I", "-I", "-D", "-D"]


def test_failed_cleanup_remains_tracked_for_retry() -> None:
    runner = RecordingRunner(fail_at=9)
    partition = DockerEgressPartition(PEERS, runner=runner)
    partition.isolate()

    with pytest.raises(RuntimeError, match="cleanup failed"):
        partition.heal()

    assert partition.active
    runner.fail_at = None
    partition.heal()
    assert not partition.active
    actions = [command[10] for command, _ in runner.commands]
    assert actions.count("-D") == 5


@pytest.mark.parametrize(
    "peers",
    [
        (),
        ("172.30.0.11", "172.30.0.11"),
        ("127.0.0.1",),
        ("8.8.8.8",),
        ("not-an-ip",),
        tuple(f"172.30.0.{index}" for index in range(1, 10)),
    ],
)
def test_rejects_unsafe_or_unbounded_peer_sets(peers: tuple[str, ...]) -> None:
    with pytest.raises(ValueError):
        DockerEgressPartition(peers)


def test_subprocess_runner_bounds_and_redacts_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def failed(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert kwargs["timeout"] == 4
        assert kwargs["capture_output"] is True
        return subprocess.CompletedProcess(
            args[0], 1, stdout="secret", stderr="failed\nrule"
        )

    monkeypatch.setattr(subprocess, "run", failed)
    with pytest.raises(RuntimeError, match="failed rule") as captured:
        run_command(["docker", "compose"], 4)
    assert "secret" not in str(captured.value)
