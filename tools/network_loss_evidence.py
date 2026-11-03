"""Bounded aggregate evidence for a controlled partial-loss experiment."""

from __future__ import annotations

import math
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any

from tools.docker_netem_impairment import MAX_COUNTER, QdiscTrafficDelta


Probe = Callable[[], bool]
Clock = Callable[[], int]
CONFIDENCE_Z_99 = 2.5758293035489004


@dataclass(frozen=True, slots=True)
class ProbeOutcomeSummary:
    """Bounded application outcomes; individual attempts are not retained."""

    attempts: int
    successes: int
    failures: int
    elapsed_ms: int

    def __post_init__(self) -> None:
        if (
            isinstance(self.attempts, bool)
            or not isinstance(self.attempts, int)
            or not 32 <= self.attempts <= 512
        ):
            raise ValueError("probe attempts must be in [32, 512]")
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in (self.successes, self.failures)
        ):
            raise ValueError("probe outcome counts must be non-negative")
        if self.successes + self.failures != self.attempts:
            raise ValueError("probe outcome counts do not match attempts")
        if (
            isinstance(self.elapsed_ms, bool)
            or not isinstance(self.elapsed_ms, int)
            or not 1 <= self.elapsed_ms <= 60_000
        ):
            raise ValueError("probe elapsed_ms must be in [1, 60000]")


@dataclass(frozen=True, slots=True)
class PartialLossBenchmarkEvidence:
    """Privacy-reduced benchmark receipt with a packet-frequency sanity check."""

    configured_loss_percent: int
    seed: int
    probe_outcomes: ProbeOutcomeSummary
    qdisc_attempted_packets: int
    qdisc_forwarded_packets: int
    qdisc_dropped_packets: int
    qdisc_bytes: int
    qdisc_overlimits: int
    observed_drop_basis_points: int
    drop_interval_min_basis_points: int
    drop_interval_max_basis_points: int
    confidence_level_percent: int = 99

    def __post_init__(self) -> None:
        if (
            isinstance(self.configured_loss_percent, bool)
            or not isinstance(self.configured_loss_percent, int)
            or not 1 <= self.configured_loss_percent <= 99
        ):
            raise ValueError("configured loss must be in [1, 99]")
        if (
            isinstance(self.seed, bool)
            or not isinstance(self.seed, int)
            or not 1 <= self.seed <= MAX_COUNTER
        ):
            raise ValueError("seed must be an unsigned nonzero 64-bit integer")
        if not isinstance(self.probe_outcomes, ProbeOutcomeSummary):
            raise ValueError("probe_outcomes must be a validated summary")
        if any(
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value <= MAX_COUNTER
            for value in (
                self.qdisc_attempted_packets,
                self.qdisc_forwarded_packets,
                self.qdisc_dropped_packets,
                self.qdisc_bytes,
                self.qdisc_overlimits,
            )
        ):
            raise ValueError("qdisc evidence contains an invalid counter")
        if (
            self.qdisc_forwarded_packets + self.qdisc_dropped_packets
            != self.qdisc_attempted_packets
        ):
            raise ValueError("qdisc packet counts do not match attempts")
        if any(
            isinstance(value, bool) or not isinstance(value, int)
            for value in (
                self.observed_drop_basis_points,
                self.drop_interval_min_basis_points,
                self.drop_interval_max_basis_points,
                self.confidence_level_percent,
            )
        ) or not (
            0
            <= self.drop_interval_min_basis_points
            <= self.observed_drop_basis_points
            <= self.drop_interval_max_basis_points
            <= 10_000
        ):
            raise ValueError("drop frequency evidence is invalid")
        if self.confidence_level_percent != 99:
            raise ValueError("partial-loss evidence requires 99 percent confidence")

    def as_dict(self) -> dict[str, Any]:
        """Return bounded aggregates without endpoints, payloads, or raw timings."""
        return asdict(self)


def observe_probe_outcomes(
    probe: Probe,
    *,
    attempts: int = 128,
    max_duration_seconds: int = 30,
    clock_ns: Clock = time.perf_counter_ns,
) -> ProbeOutcomeSummary:
    """Execute a fixed number of probes under one wall-clock budget."""
    if isinstance(attempts, bool) or not isinstance(attempts, int):
        raise ValueError("attempts must be an integer in [32, 512]")
    if not 32 <= attempts <= 512:
        raise ValueError("attempts must be an integer in [32, 512]")
    if (
        isinstance(max_duration_seconds, bool)
        or not isinstance(max_duration_seconds, int)
        or not 5 <= max_duration_seconds <= 60
    ):
        raise ValueError("max_duration_seconds must be an integer in [5, 60]")

    started_ns = clock_ns()
    successes = 0
    for _ in range(attempts):
        outcome = probe()
        if not isinstance(outcome, bool):
            raise RuntimeError("partial-loss probe returned a non-boolean outcome")
        successes += int(outcome)
        elapsed_ns = clock_ns() - started_ns
        if elapsed_ns <= 0 or elapsed_ns > max_duration_seconds * 1_000_000_000:
            raise RuntimeError("partial-loss probe exceeded its wall-clock budget")

    elapsed_ms = (elapsed_ns + 999_999) // 1_000_000
    return ProbeOutcomeSummary(
        attempts=attempts,
        successes=successes,
        failures=attempts - successes,
        elapsed_ms=elapsed_ms,
    )


def verify_partial_loss_benchmark(
    outcomes: ProbeOutcomeSummary,
    traffic: QdiscTrafficDelta,
    *,
    configured_loss_percent: int,
    seed: int,
) -> PartialLossBenchmarkEvidence:
    """Fail closed on missing pass/drop evidence or an implausible loss frequency."""
    if (
        isinstance(configured_loss_percent, bool)
        or not isinstance(configured_loss_percent, int)
        or not 1 <= configured_loss_percent <= 99
    ):
        raise ValueError("configured_loss_percent must be an integer in [1, 99]")
    if isinstance(seed, bool) or not isinstance(seed, int) or not 1 <= seed < 1 << 64:
        raise ValueError("seed must be an unsigned nonzero 64-bit integer")
    if outcomes.successes < 1:
        raise RuntimeError("partial-loss benchmark observed no successful probes")
    if traffic.packets < 1 or traffic.drops < 1:
        raise RuntimeError(
            "partial-loss benchmark requires forwarded and dropped packets"
        )

    attempted_packets = traffic.packets + traffic.drops
    if attempted_packets > MAX_COUNTER:
        raise RuntimeError("partial-loss packet-attempt count overflowed")
    if attempted_packets < outcomes.attempts:
        raise RuntimeError(
            "partial-loss benchmark recorded insufficient packet attempts"
        )

    interval_min, interval_max = _wilson_interval_basis_points(
        traffic.drops,
        attempted_packets,
    )
    configured_basis_points = configured_loss_percent * 100
    if not interval_min <= configured_basis_points <= interval_max:
        raise RuntimeError(
            "observed qdisc loss frequency is inconsistent with the configured policy"
        )

    observed_basis_points = (
        traffic.drops * 10_000 + attempted_packets // 2
    ) // attempted_packets
    return PartialLossBenchmarkEvidence(
        configured_loss_percent=configured_loss_percent,
        seed=seed,
        probe_outcomes=outcomes,
        qdisc_attempted_packets=attempted_packets,
        qdisc_forwarded_packets=traffic.packets,
        qdisc_dropped_packets=traffic.drops,
        qdisc_bytes=traffic.bytes,
        qdisc_overlimits=traffic.overlimits,
        observed_drop_basis_points=observed_basis_points,
        drop_interval_min_basis_points=interval_min,
        drop_interval_max_basis_points=interval_max,
    )


def _wilson_interval_basis_points(drops: int, attempts: int) -> tuple[int, int]:
    """Return a conservative two-sided 99% Wilson score interval."""
    if not 0 <= drops <= attempts or attempts < 1:
        raise ValueError("drop counts must describe at least one packet attempt")
    proportion = drops / attempts
    z_squared = CONFIDENCE_Z_99**2
    denominator = 1 + z_squared / attempts
    center = (proportion + z_squared / (2 * attempts)) / denominator
    margin = (
        CONFIDENCE_Z_99
        * math.sqrt(
            proportion * (1 - proportion) / attempts
            + z_squared / (4 * attempts * attempts)
        )
        / denominator
    )
    return (
        max(0, math.floor((center - margin) * 10_000)),
        min(10_000, math.ceil((center + margin) * 10_000)),
    )
