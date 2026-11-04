from __future__ import annotations

import hashlib
import json
import subprocess

import pytest

from tools.docker_netem_impairment import (
    HANDLE,
    MAX_COUNTER,
    RUNTIME_FINGERPRINT_SCHEMA,
    SERVICE,
    DockerNetemImpairment,
    NetemRuntimeFingerprint,
    QdiscTrafficDelta,
    run_command,
)


def qdisc_document(
    *,
    delay: float = 0.2,
    jitter: float = 0.02,
    reorder: float = 0.25,
    correlation: float = 0.5,
    loss: float | None = None,
    seed: int | None = None,
    limit: object = 1_000,
    packets: int = 0,
    bytes_: int = 0,
    drops: int = 0,
    overlimits: int = 0,
) -> str:
    options: dict[str, object] = {
        "limit": limit,
        "delay": {"delay": delay, "jitter": jitter, "correlation": 0},
        "gap": 1,
    }
    if reorder:
        options["reorder"] = {
            "reorder": reorder,
            "correlation": correlation,
        }
    if loss is not None:
        options["loss-random"] = {"loss": loss, "correlation": 0}
    if seed is not None:
        options["seed"] = seed
    return json.dumps(
        [
            {
                "kind": "netem",
                "handle": HANDLE,
                "root": True,
                "packets": packets,
                "bytes": bytes_,
                "drops": drops,
                "overlimits": overlimits,
                "options": options,
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
        "limit",
        "1000",
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


def test_fingerprints_bounded_kernel_and_iproute2_versions_privately() -> None:
    commands: list[list[str]] = []

    def runner(command: list[str], _timeout: float) -> str:
        commands.append(command)
        if command[-2:] == ["uname", "-r"]:
            return "6.11.0-1018-azure\n"
        if command[-2:] == ["tc", "-Version"]:
            return "tc utility, iproute2-6.11.0, libbpf 1.4.7\n"
        raise AssertionError(command)

    fingerprint = DockerNetemImpairment(runner=runner).runtime_fingerprint()

    assert fingerprint.schema_version == RUNTIME_FINGERPRINT_SCHEMA
    assert (
        fingerprint.kernel_release_sha256
        == hashlib.sha256(b"6.11.0-1018-azure").hexdigest()
    )
    assert (
        fingerprint.tc_version_sha256
        == hashlib.sha256(b"tc utility, iproute2-6.11.0, libbpf 1.4.7").hexdigest()
    )
    assert len(fingerprint.environment_sha256) == 64
    serialized = json.dumps(fingerprint.as_dict(), sort_keys=True)
    assert "6.11.0" not in serialized
    assert all(
        command[:7] == ["docker", "compose", "exec", "-T", "--user", "0", SERVICE]
        for command in commands
    )


@pytest.mark.parametrize(
    ("kernel_release", "tc_version"),
    [
        ("", "tc utility, iproute2-6.11.0"),
        ("6.11.0\nsecond-line", "tc utility, iproute2-6.11.0"),
        ("6.11.0", "iproute2-6.11.0"),
        ("6.11.0", "tc utility, iproute2-6.11.0\nforged"),
        ("6.11.0-λ", "tc utility, iproute2-6.11.0"),
    ],
)
def test_rejects_malformed_runtime_provenance(
    kernel_release: str,
    tc_version: str,
) -> None:
    def runner(command: list[str], _timeout: float) -> str:
        return kernel_release if command[-2:] == ["uname", "-r"] else tc_version

    with pytest.raises(RuntimeError, match="malformed|canonical ASCII"):
        DockerNetemImpairment(runner=runner).runtime_fingerprint()


def test_rejects_tampered_runtime_fingerprint_commitment() -> None:
    with pytest.raises(ValueError, match="commitment"):
        NetemRuntimeFingerprint(
            kernel_release_sha256="a" * 64,
            tc_version_sha256="b" * 64,
            environment_sha256="c" * 64,
        )


def test_proves_traffic_crossed_the_verified_impairment() -> None:
    runner = RecordingRunner(
        show_documents=[
            qdisc_document(packets=10, bytes_=900, drops=2, overlimits=3),
            qdisc_document(packets=14, bytes_=1_600, drops=5, overlimits=7),
            "[]",
        ]
    )
    impairment = DockerNetemImpairment(runner=runner)

    impairment.apply()
    assert impairment.verify_traffic_observed() == QdiscTrafficDelta(
        packets=4,
        bytes=700,
        drops=3,
        overlimits=4,
    )
    impairment.clear()


def test_requires_nonzero_drop_evidence_for_explicit_loss_policy() -> None:
    runner = RecordingRunner(
        show_documents=[
            qdisc_document(
                reorder=0,
                correlation=0,
                loss=1.0,
                packets=10,
                bytes_=900,
            ),
            qdisc_document(
                reorder=0,
                correlation=0,
                loss=1.0,
                packets=10,
                bytes_=900,
                drops=3,
            ),
            "[]",
        ]
    )
    impairment = DockerNetemImpairment(
        reorder_percent=0,
        reorder_correlation_percent=0,
        loss_percent=100,
        runner=runner,
    )

    impairment.apply()
    assert (
        impairment.verify_traffic_observed(require_drops=True, minimum_packets=3).drops
        == 3
    )
    impairment.clear()

    assert runner.commands[0][0][-3:] == ["loss", "random", "100%"]


def test_applies_and_verifies_seeded_partial_loss_policy() -> None:
    runner = RecordingRunner(
        show_documents=[
            qdisc_document(
                delay=0.01,
                jitter=0.0,
                reorder=0,
                correlation=0,
                loss=0.2,
                seed=12_648_430,
            ),
            "[]",
        ]
    )
    impairment = DockerNetemImpairment(
        delay_ms=10,
        jitter_ms=0,
        reorder_percent=0,
        reorder_correlation_percent=0,
        loss_percent=20,
        seed=12_648_430,
        runner=runner,
    )

    impairment.apply()
    impairment.clear()

    assert runner.commands[0][0][-5:] == [
        "loss",
        "random",
        "20%",
        "seed",
        "12648430",
    ]


def test_accepts_kernel_generated_seed_when_policy_does_not_pin_one() -> None:
    impairment = DockerNetemImpairment(
        runner=RecordingRunner(live_document=qdisc_document(seed=98_765))
    )

    impairment.apply()
    impairment.clear()


@pytest.mark.parametrize("observed_limit", [None, 999, True])
def test_rejects_missing_or_mismatched_live_queue_limit(
    observed_limit: object,
) -> None:
    impairment = DockerNetemImpairment(
        runner=RecordingRunner(live_document=qdisc_document(limit=observed_limit))
    )

    with pytest.raises(RuntimeError, match="queue limit does not match"):
        impairment.apply()

    assert not impairment.active


@pytest.mark.parametrize("observed_seed", [None, 12_648_431, True])
def test_rejects_missing_or_mismatched_live_seed(observed_seed: object) -> None:
    runner = RecordingRunner(
        live_document=qdisc_document(
            reorder=0,
            correlation=0,
            loss=0.2,
            seed=observed_seed,  # type: ignore[arg-type]
        )
    )
    impairment = DockerNetemImpairment(
        reorder_percent=0,
        reorder_correlation_percent=0,
        loss_percent=20,
        seed=12_648_430,
        runner=runner,
    )

    with pytest.raises(RuntimeError, match="seed does not match"):
        impairment.apply()

    assert not impairment.active


def test_rejects_zero_drop_evidence_for_explicit_loss_policy() -> None:
    runner = RecordingRunner(
        show_documents=[
            qdisc_document(reorder=0, correlation=0, loss=1.0),
            qdisc_document(
                reorder=0,
                correlation=0,
                loss=1.0,
                packets=1,
                bytes_=100,
            ),
            "[]",
        ]
    )
    impairment = DockerNetemImpairment(
        reorder_percent=0,
        reorder_correlation_percent=0,
        loss_percent=100,
        runner=runner,
    )
    impairment.apply()

    with pytest.raises(RuntimeError, match="no packet drops"):
        impairment.verify_traffic_observed(require_drops=True)

    impairment.clear()


def test_rejects_insufficient_loss_probe_volume() -> None:
    runner = RecordingRunner(
        show_documents=[
            qdisc_document(reorder=0, correlation=0, loss=1.0),
            qdisc_document(reorder=0, correlation=0, loss=1.0, drops=1),
            "[]",
        ]
    )
    impairment = DockerNetemImpairment(
        reorder_percent=0,
        reorder_correlation_percent=0,
        loss_percent=100,
        runner=runner,
    )
    impairment.apply()

    with pytest.raises(RuntimeError, match="insufficient traffic"):
        impairment.verify_traffic_observed(require_drops=True, minimum_packets=3)

    impairment.clear()


def test_drop_gate_requires_a_loss_policy() -> None:
    impairment = DockerNetemImpairment(runner=RecordingRunner())
    impairment.apply()

    with pytest.raises(RuntimeError, match="requires a configured loss policy"):
        impairment.verify_traffic_observed(require_drops=True)

    impairment.clear()


def test_enforces_bounded_minimum_packet_volume() -> None:
    runner = RecordingRunner(
        show_documents=[
            qdisc_document(packets=10, bytes_=900),
            qdisc_document(packets=11, bytes_=1_000),
            "[]",
        ]
    )
    impairment = DockerNetemImpairment(runner=runner)
    impairment.apply()

    with pytest.raises(RuntimeError, match="no reconnection traffic"):
        impairment.verify_traffic_observed(minimum_packets=2)

    impairment.clear()


@pytest.mark.parametrize("minimum_packets", [True, 0, 1_001, 1.5])
def test_rejects_invalid_minimum_packet_volume(minimum_packets: object) -> None:
    impairment = DockerNetemImpairment(runner=RecordingRunner())

    with pytest.raises(ValueError, match="minimum_packets"):
        impairment.verify_traffic_observed(  # type: ignore[arg-type]
            minimum_packets=minimum_packets
        )


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
    "current",
    [
        qdisc_document(packets=11, bytes_=901, drops=4, overlimits=7),
        qdisc_document(packets=11, bytes_=901, drops=5, overlimits=6),
    ],
)
def test_rejects_regressing_drop_or_overlimit_counters(current: str) -> None:
    runner = RecordingRunner(
        show_documents=[
            qdisc_document(packets=10, bytes_=900, drops=5, overlimits=7),
            current,
            "[]",
        ]
    )
    impairment = DockerNetemImpairment(runner=runner)
    impairment.apply()

    with pytest.raises(RuntimeError, match="counters regressed"):
        impairment.verify_traffic_observed()

    impairment.clear()


@pytest.mark.parametrize(
    "counter_overrides",
    [
        {"packets": True},
        {"packets": -1},
        {"bytes_": -1},
        {"drops": True},
        {"overlimits": MAX_COUNTER + 1},
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
        {"reorder_percent": 0, "reorder_correlation_percent": 1},
        {"reorder_correlation_percent": 101},
        {"loss_percent": -1},
        {"loss_percent": 101},
        {"seed": 1},
        {"loss_percent": 20, "seed": True},
        {"loss_percent": 20, "seed": 0},
        {"loss_percent": 20, "seed": MAX_COUNTER + 1},
        {"queue_limit_packets": True},
        {"queue_limit_packets": 0},
        {"queue_limit_packets": 100_001},
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
