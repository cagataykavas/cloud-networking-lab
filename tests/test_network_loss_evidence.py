from __future__ import annotations

import pytest

from tools.docker_netem_impairment import NetemRuntimeFingerprint, QdiscTrafficDelta
from tools.network_loss_evidence import (
    ProbeOutcomeSummary,
    observe_probe_outcomes,
    verify_partial_loss_benchmark,
)


RUNTIME_FINGERPRINT = NetemRuntimeFingerprint(
    kernel_release_sha256="a" * 64,
    tc_version_sha256="b" * 64,
    environment_sha256="e0916a8d67df9cb2e4bbbd4e5c1366b2aad82c7130182775b334ca6f4005c69f",
)


def test_observes_only_bounded_aggregate_probe_outcomes() -> None:
    outcomes = iter([True, True, True, False] * 32)
    ticks = iter(range(0, 129_000_000, 1_000_000))

    summary = observe_probe_outcomes(
        lambda: next(outcomes),
        attempts=128,
        clock_ns=lambda: next(ticks),
    )

    assert summary == ProbeOutcomeSummary(
        attempts=128,
        successes=96,
        failures=32,
        elapsed_ms=128,
    )


def test_verifies_seeded_partial_loss_with_a_99_percent_interval() -> None:
    evidence = verify_partial_loss_benchmark(
        ProbeOutcomeSummary(
            attempts=128,
            successes=124,
            failures=4,
            elapsed_ms=700,
        ),
        QdiscTrafficDelta(
            packets=800,
            bytes=72_000,
            drops=200,
            overlimits=0,
        ),
        configured_loss_percent=20,
        seed=12_648_430,
        runtime_fingerprint=RUNTIME_FINGERPRINT,
    )

    assert evidence.observed_drop_basis_points == 2_000
    assert evidence.drop_interval_min_basis_points < 2_000
    assert evidence.drop_interval_max_basis_points > 2_000
    assert evidence.qdisc_attempted_packets == 1_000
    assert evidence.runtime_fingerprint == RUNTIME_FINGERPRINT
    assert evidence.as_dict()["runtime_fingerprint"] == RUNTIME_FINGERPRINT.as_dict()
    assert evidence.as_dict()["probe_outcomes"] == {
        "attempts": 128,
        "successes": 124,
        "failures": 4,
        "elapsed_ms": 700,
    }


@pytest.mark.parametrize(
    ("outcomes", "traffic", "message"),
    [
        (
            ProbeOutcomeSummary(32, 0, 32, 10),
            QdiscTrafficDelta(30, 1_000, 10, 0),
            "no successful probes",
        ),
        (
            ProbeOutcomeSummary(32, 32, 0, 10),
            QdiscTrafficDelta(40, 1_000, 0, 0),
            "forwarded and dropped",
        ),
        (
            ProbeOutcomeSummary(32, 32, 0, 10),
            QdiscTrafficDelta(10, 1_000, 10, 0),
            "insufficient packet attempts",
        ),
        (
            ProbeOutcomeSummary(128, 128, 0, 10),
            QdiscTrafficDelta(995, 1_000, 5, 0),
            "inconsistent with the configured policy",
        ),
    ],
)
def test_rejects_incomplete_or_implausible_partial_loss_evidence(
    outcomes: ProbeOutcomeSummary,
    traffic: QdiscTrafficDelta,
    message: str,
) -> None:
    with pytest.raises(RuntimeError, match=message):
        verify_partial_loss_benchmark(
            outcomes,
            traffic,
            configured_loss_percent=20,
            seed=12_648_430,
            runtime_fingerprint=RUNTIME_FINGERPRINT,
        )


@pytest.mark.parametrize("attempts", [True, 31, 513, 32.0])
def test_rejects_unbounded_probe_attempt_counts(attempts: object) -> None:
    with pytest.raises(ValueError, match="attempts"):
        observe_probe_outcomes(lambda: True, attempts=attempts)  # type: ignore[arg-type]


def test_rejects_non_boolean_probe_outcomes() -> None:
    with pytest.raises(RuntimeError, match="non-boolean"):
        observe_probe_outcomes(lambda: 1, attempts=32)  # type: ignore[return-value]


def test_rejects_probe_window_that_exceeds_the_deadline() -> None:
    ticks = iter([0, 6_000_000_001])
    with pytest.raises(RuntimeError, match="wall-clock budget"):
        observe_probe_outcomes(
            lambda: True,
            attempts=32,
            max_duration_seconds=5,
            clock_ns=lambda: next(ticks),
        )


@pytest.mark.parametrize(
    ("loss_percent", "seed"),
    [(True, 1), (0, 1), (100, 1), (20, True), (20, 0), (20, 1 << 64)],
)
def test_rejects_invalid_partial_loss_policy(
    loss_percent: object, seed: object
) -> None:
    with pytest.raises(ValueError):
        verify_partial_loss_benchmark(
            ProbeOutcomeSummary(32, 30, 2, 10),
            QdiscTrafficDelta(80, 1_000, 20, 0),
            configured_loss_percent=loss_percent,  # type: ignore[arg-type]
            seed=seed,  # type: ignore[arg-type]
            runtime_fingerprint=RUNTIME_FINGERPRINT,
        )


def test_rejects_unvalidated_runtime_fingerprint() -> None:
    with pytest.raises(ValueError, match="runtime_fingerprint"):
        verify_partial_loss_benchmark(
            ProbeOutcomeSummary(32, 30, 2, 10),
            QdiscTrafficDelta(80, 1_000, 20, 0),
            configured_loss_percent=20,
            seed=12_648_430,
            runtime_fingerprint="untrusted",  # type: ignore[arg-type]
        )
