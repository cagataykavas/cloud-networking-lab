"""Bounded, aggregate round-trip evidence for controlled network faults."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any


Probe = Callable[[], object]
Clock = Callable[[], int]


@dataclass(frozen=True, slots=True)
class LatencyWindow:
    """Privacy-reduced latency summary; individual probe timings are discarded."""

    sample_count: int
    median_us: int
    p95_us: int

    def __post_init__(self) -> None:
        if not 3 <= self.sample_count <= 31 or self.sample_count % 2 == 0:
            raise ValueError("latency sample_count must be odd and in [3, 31]")
        if self.median_us < 1 or self.p95_us < self.median_us:
            raise ValueError("latency summary is invalid")


@dataclass(frozen=True, slots=True)
class LatencyShiftEvidence:
    """Aggregate evidence that a configured delay appeared and then recovered."""

    baseline: LatencyWindow
    impaired: LatencyWindow
    recovery: LatencyWindow
    median_shift_us: int
    minimum_expected_shift_us: int
    recovery_delta_us: int
    recovery_budget_us: int

    def as_dict(self) -> dict[str, Any]:
        """Return a deterministic receipt fragment without raw samples."""
        return {
            "baseline": asdict(self.baseline),
            "impaired": asdict(self.impaired),
            "recovery": asdict(self.recovery),
            "median_shift_us": self.median_shift_us,
            "minimum_expected_shift_us": self.minimum_expected_shift_us,
            "recovery_delta_us": self.recovery_delta_us,
            "recovery_budget_us": self.recovery_budget_us,
        }


def observe_round_trip_latency(
    probe: Probe,
    *,
    sample_count: int = 7,
    max_sample_ms: int = 2_000,
    clock_ns: Clock = time.perf_counter_ns,
) -> LatencyWindow:
    """Run a bounded probe window and retain only median and p95 latency."""
    if not 3 <= sample_count <= 31 or sample_count % 2 == 0:
        raise ValueError("sample_count must be odd and in [3, 31]")
    if not 1 <= max_sample_ms <= 5_000:
        raise ValueError("max_sample_ms must be in [1, 5000]")

    samples_us: list[int] = []
    for _ in range(sample_count):
        started_ns = clock_ns()
        if probe() is not True:
            raise RuntimeError("latency probe did not acknowledge the round trip")
        elapsed_ns = clock_ns() - started_ns
        if elapsed_ns <= 0 or elapsed_ns > max_sample_ms * 1_000_000:
            raise RuntimeError("latency probe duration was outside the bounded window")
        samples_us.append((elapsed_ns + 999) // 1_000)

    samples_us.sort()
    median_us = samples_us[len(samples_us) // 2]
    p95_index = ((95 * len(samples_us) + 99) // 100) - 1
    return LatencyWindow(
        sample_count=len(samples_us),
        median_us=median_us,
        p95_us=samples_us[p95_index],
    )


def verify_latency_shift(
    baseline: LatencyWindow,
    impaired: LatencyWindow,
    recovery: LatencyWindow,
    *,
    configured_delay_ms: int,
    configured_jitter_ms: int,
) -> LatencyShiftEvidence:
    """Fail closed unless delay is visible and cleanup restores the baseline band."""
    if len({baseline.sample_count, impaired.sample_count, recovery.sample_count}) != 1:
        raise ValueError("latency windows must use the same sample_count")
    if not 10 <= configured_delay_ms <= 2_000:
        raise ValueError("configured_delay_ms must be in [10, 2000]")
    if not 0 <= configured_jitter_ms <= configured_delay_ms:
        raise ValueError("configured_jitter_ms must be in [0, configured_delay_ms]")

    minimum_expected_shift_us = max(
        5_000,
        (configured_delay_ms - (3 * configured_jitter_ms)) * 1_000,
    )
    median_shift_us = impaired.median_us - baseline.median_us
    if median_shift_us < minimum_expected_shift_us:
        raise RuntimeError("configured impairment was not visible in median latency")

    recovery_budget_us = max(25_000, configured_delay_ms * 250)
    recovery_delta_us = recovery.median_us - baseline.median_us
    if recovery_delta_us > recovery_budget_us:
        raise RuntimeError(
            "round-trip latency did not recover after impairment cleanup"
        )

    return LatencyShiftEvidence(
        baseline=baseline,
        impaired=impaired,
        recovery=recovery,
        median_shift_us=median_shift_us,
        minimum_expected_shift_us=minimum_expected_shift_us,
        recovery_delta_us=recovery_delta_us,
        recovery_budget_us=recovery_budget_us,
    )
