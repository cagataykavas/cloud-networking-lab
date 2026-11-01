from __future__ import annotations

import json
import subprocess

import pytest

from tools.docker_netem_impairment import (
    HANDLE,
    SERVICE,
    DockerNetemImpairment,
    QdiscTrafficDelta,
    run_command,
)


def qdisc_document(
    *,
    delay: float = 0.2,
    jitter: float = 0.02,
    reorder: float = 0.25,
    correlation: float = 0.5,
    packets: int = 0,
    bytes_: int = 0,
) -> str:
    return json.dumps(
        [
            {
                "kind": "netem",
                "handle": HANDLE,
                "root": True,
                "packets": packets,
                "bytes": bytes_,
                "options": {
                    "limit": 1_000,
                    "delay": {"delay": delay, "jitter": jitter, "correlation": 0},
                    "reorder": {
                        "reorder": reorder,
                        "correlation": correlation,
                    },
                    "gap": 1,
                },
            }
        ]
    )


class RecordingRunner:
    def __init__(
        self,
        *,
        live_document: str | None = None,
        show_documents: list[str] | None = None,
        fail_at: int | None = None,
    ) -> None:
        self.commands: list[tuple[list[str], float]] = []
        self.live_document = live_document or qdisc_document()
        self.show_documents = iter(show_documents) if show_documents else None
        self.fail_at = fail_at

    def __call__(self, command: list[str], timeout_seconds: float) -> str:
        self.commands.append((command, timeout_seconds))
        if self.fail_at == len(self.commands):
            raise RuntimeError("injected command failure")
        if "show" in command:
            if self.show_documents is not None:
                return next(self.show_documents)
            return self.live_document if len(self.commands) == 2 else "[]"
        return ""


def test_applies_verifies_and_removes_exact_netem_policy() -> None:
    runner = RecordingRunner()
    impairment = DockerNetemImpairment(runner=runner, timeout_seconds=7)

    impairment.apply()
    assert impairment.active
    impairment.clear()
    assert not impairment.active
    impairment.clear()

    commands = [command for command, _ in runner.commands]
    assert len(commands) == 4
    assert all(
        command[:7] == ["docker", "compose", "exec", "-T", "--user", "0", SERVICE]
        for command in commands
    )
    assert commands[0][7:] == [
        "tc",
        "qdisc",
        "add",
        "dev",
        "eth0",
        "root",
        "handle",
        "1:",
        "netem",
        "delay",
        "200ms",
        "20ms",
        "reorder",
        "25%",
        "50%",
    ]
    assert commands[1][7:] == [
        "tc",
        "-statistics",
        "-json",
        "qdisc",
        "show",
        "dev",
        "eth0",
    ]
    assert commands[2][7:] == [
        "tc",
        "qdisc",
        "del",
        "dev",
        "eth0",
        "root",
        "handle",
        "1:",
    ]
    assert commands[3] == commands[1]
    assert all(timeout == 7 for _, timeout in runner.commands)


def test_proves_traffic_crossed_the_verified_impairment() -> None:
    runner = RecordingRunner(
        show_documents=[
            qdisc_document(packets=10, bytes_=900),
            qdisc_document(packets=14, bytes_=1_600),
            "[]",
        ]
    )
    impairment = DockerNetemImpairment(runner=runner)

    impairment.apply()
    assert impairment.verify_traffic_observed() == QdiscTrafficDelta(
        packets=4,
        bytes=700,
    )
    impairment.clear()


@pytest.mark.parametrize(
    ("current", "message"),
    [
        (qdisc_document(packets=10, bytes_=900), "no reconnection traffic"),
        (qdisc_document(packets=9, bytes_=900), "counters regressed"),
    ],
)
def test_rejects_absent_or_regressing_traffic(
    current: str,
    message: str,
) -> None:
    runner = RecordingRunner(
        show_documents=[qdisc_document(packets=10, bytes_=900), current, "[]"]
    )
    impairment = DockerNetemImpairment(runner=runner)
    impairment.apply()

    with pytest.raises(RuntimeError, match=message):
        impairment.verify_traffic_observed()

    impairment.clear()


@pytest.mark.parametrize(
    "counter_overrides",
    [
        {"packets": True},
        {"packets": -1},
        {"bytes_": -1},
    ],
)
def test_rejects_invalid_live_counters(counter_overrides: dict[str, object]) -> None:
    document = qdisc_document(**counter_overrides)  # type: ignore[arg-type]
    impairment = DockerNetemImpairment(runner=RecordingRunner(live_document=document))

    with pytest.raises(RuntimeError, match="counter is invalid"):
        impairment.apply()

    assert not impairment.active


def test_rolls_back_policy_that_does_not_match_live_qdisc() -> None:
    runner = RecordingRunner(live_document=qdisc_document(delay=0.4))
    impairment = DockerNetemImpairment(runner=runner)

    with pytest.raises(RuntimeError, match="does not match policy"):
        impairment.apply()

    assert not impairment.active
    assert [
        "show" if "show" in command else command[9] for command, _ in runner.commands
    ] == [
        "add",
        "show",
        "del",
        "show",
    ]


def test_failed_cleanup_remains_active_for_retry() -> None:
    runner = RecordingRunner(fail_at=3)
    impairment = DockerNetemImpairment(runner=runner)
    impairment.apply()

    with pytest.raises(RuntimeError, match="cleanup failed"):
        impairment.clear()

    assert impairment.active
    runner.fail_at = None
    impairment.clear()
    assert not impairment.active


@pytest.mark.parametrize(
    "overrides",
    [
        {"interface": "eth0;rm"},
        {"delay_ms": 9},
        {"delay_ms": 2_001},
        {"delay_ms": 20, "jitter_ms": 21},
        {"reorder_percent": 0},
        {"reorder_percent": 51},
        {"reorder_correlation_percent": 101},
        {"timeout_seconds": 31},
    ],
)
def test_rejects_unsafe_or_unbounded_policies(overrides: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        DockerNetemImpairment(**overrides)  # type: ignore[arg-type]


@pytest.mark.parametrize("document", ["not-json", "{}", "[1]", "[]"])
def test_rejects_malformed_or_missing_live_qdisc(document: str) -> None:
    impairment = DockerNetemImpairment(runner=RecordingRunner(live_document=document))
    with pytest.raises(RuntimeError):
        impairment.apply()
    assert not impairment.active


def test_subprocess_runner_bounds_and_redacts_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def failed(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert kwargs["timeout"] == 4
        assert kwargs["capture_output"] is True
        return subprocess.CompletedProcess(
            args[0], 1, stdout="secret", stderr="tc failed\npolicy"
        )

    monkeypatch.setattr(subprocess, "run", failed)
    with pytest.raises(RuntimeError, match="tc failed policy") as captured:
        run_command(["docker", "compose"], 4)
    assert "secret" not in str(captured.value)
