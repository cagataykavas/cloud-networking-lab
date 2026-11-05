"""Bounded aggregate evidence for a controlled partial-loss experiment."""

from __future__ import annotations

import hashlib
import json
import math
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any

from tools.docker_netem_impairment import (
    MAX_COUNTER,
    NetemRuntimeFingerprint,
    QdiscTrafficDelta,
)


Probe = Callable[[], bool]
Clock = Callable[[], int]
CONFIDENCE_Z_99 = 2.5758293035489004
PARTIAL_LOSS_COMPARISON_SCHEMA = "netem-partial-loss-comparison/v1"

_EVIDENCE_FIELDS = frozenset(
    {
        "confidence_level_percent",
        "configured_loss_percent",
        "drop_interval_max_basis_points",
        "drop_interval_min_basis_points",
        "observed_drop_basis_points",
        "probe_outcomes",
        "qdisc_attempted_packets",
        "qdisc_bytes",
        "qdisc_dropped_packets",
        "qdisc_forwarded_packets",
        "qdisc_overlimits",
        "runtime_fingerprint",
        "seed",
    }
)
_FINGERPRINT_FIELDS = frozenset(
    {
        "environment_sha256",
        "kernel_release_sha256",
        "schema_version",
        "tc_version_sha256",
    }
)
_OUTCOME_FIELDS = frozenset({"attempts", "elapsed_ms", "failures", "successes"})


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


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
    runtime_fingerprint: NetemRuntimeFingerprint
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
        if not isinstance(self.runtime_fingerprint, NetemRuntimeFingerprint):
            raise ValueError("runtime_fingerprint must be validated netem provenance")
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

        expected_observed = _rate_basis_points(
            self.qdisc_dropped_packets,
            self.qdisc_attempted_packets,
        )
        expected_interval = _wilson_interval_basis_points(
            self.qdisc_dropped_packets,
            self.qdisc_attempted_packets,
        )
        if (
            self.observed_drop_basis_points != expected_observed
            or (
                self.drop_interval_min_basis_points,
                self.drop_interval_max_basis_points,
            )
            != expected_interval
            or not self.drop_interval_min_basis_points
            <= self.configured_loss_percent * 100
            <= self.drop_interval_max_basis_points
        ):
            raise ValueError("partial-loss statistical commitments are invalid")

    @classmethod
    def from_dict(cls, document: object) -> PartialLossBenchmarkEvidence:
        """Reconstruct one retained receipt without trusting serialized aggregates."""
        if not isinstance(document, dict) or set(document) != _EVIDENCE_FIELDS:
            raise ValueError("partial-loss evidence fields do not match the schema")
        fingerprint = document.get("runtime_fingerprint")
        outcomes = document.get("probe_outcomes")
        if not isinstance(fingerprint, dict) or set(fingerprint) != _FINGERPRINT_FIELDS:
            raise ValueError("runtime fingerprint fields do not match the schema")
        if not isinstance(outcomes, dict) or set(outcomes) != _OUTCOME_FIELDS:
            raise ValueError("probe outcome fields do not match the schema")
        try:
            return cls(
                configured_loss_percent=document["configured_loss_percent"],
                seed=document["seed"],
                runtime_fingerprint=NetemRuntimeFingerprint(**fingerprint),
                probe_outcomes=ProbeOutcomeSummary(**outcomes),
                qdisc_attempted_packets=document["qdisc_attempted_packets"],
                qdisc_forwarded_packets=document["qdisc_forwarded_packets"],
                qdisc_dropped_packets=document["qdisc_dropped_packets"],
                qdisc_bytes=document["qdisc_bytes"],
                qdisc_overlimits=document["qdisc_overlimits"],
                observed_drop_basis_points=document["observed_drop_basis_points"],
                drop_interval_min_basis_points=document[
                    "drop_interval_min_basis_points"
                ],
                drop_interval_max_basis_points=document[
                    "drop_interval_max_basis_points"
                ],
                confidence_level_percent=document["confidence_level_percent"],
            )
        except TypeError as exc:
            raise ValueError("partial-loss evidence contains invalid values") from exc

    def as_dict(self) -> dict[str, Any]:
        """Return bounded aggregates without endpoints, payloads, or raw timings."""
        return asdict(self)

    def digest(self) -> str:
        """Commit to the exact canonical retained benchmark."""
        return hashlib.sha256(_canonical(self.as_dict())).hexdigest()


@dataclass(frozen=True, slots=True)
class PartialLossBenchmarkComparison:
    """Privacy-reduced regression decision for two compatible benchmark receipts."""

    accepted: bool
    baseline_benchmark_sha256: str
    candidate_benchmark_sha256: str
    runtime_fingerprint_sha256: str
    policy_sha256: str
    failure_rate_delta_basis_points: int
    elapsed_change_basis_points: int
    observed_drop_delta_basis_points: int
    max_failure_rate_increase_basis_points: int
    max_elapsed_increase_basis_points: int
    schema_version: str = PARTIAL_LOSS_COMPARISON_SCHEMA

    def as_dict(self) -> dict[str, Any]:
        document = asdict(self)
        document["status"] = "pass" if self.accepted else "fail"
        document["evidence_sha256"] = hashlib.sha256(_canonical(document)).hexdigest()
        return document


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
    runtime_fingerprint: NetemRuntimeFingerprint,
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
    if not isinstance(runtime_fingerprint, NetemRuntimeFingerprint):
        raise ValueError("runtime_fingerprint must be validated netem provenance")
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
        runtime_fingerprint=runtime_fingerprint,
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


def compare_partial_loss_benchmarks(
    baseline: PartialLossBenchmarkEvidence,
    candidate: PartialLossBenchmarkEvidence,
    *,
    max_failure_rate_increase_basis_points: int = 250,
    max_elapsed_increase_basis_points: int = 2_000,
) -> PartialLossBenchmarkComparison:
    """Compare only equivalent policies running on one exact runtime fingerprint."""
    if not isinstance(baseline, PartialLossBenchmarkEvidence) or not isinstance(
        candidate, PartialLossBenchmarkEvidence
    ):
        raise ValueError("benchmark comparison requires validated evidence")
    for name, value in (
        (
            "max_failure_rate_increase_basis_points",
            max_failure_rate_increase_basis_points,
        ),
        ("max_elapsed_increase_basis_points", max_elapsed_increase_basis_points),
    ):
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value <= 10_000
        ):
            raise ValueError(f"{name} must be an integer in [0, 10000]")
    if baseline.runtime_fingerprint != candidate.runtime_fingerprint:
        raise ValueError("benchmark runtime fingerprints do not match")

    baseline_policy = _comparison_policy(baseline)
    candidate_policy = _comparison_policy(candidate)
    if baseline_policy != candidate_policy:
        raise ValueError("benchmark policies do not match")

    failure_delta = _rate_basis_points(
        candidate.probe_outcomes.failures,
        candidate.probe_outcomes.attempts,
    ) - _rate_basis_points(
        baseline.probe_outcomes.failures,
        baseline.probe_outcomes.attempts,
    )
    elapsed_change = _relative_change_basis_points(
        candidate.probe_outcomes.elapsed_ms,
        baseline.probe_outcomes.elapsed_ms,
    )
    accepted = (
        failure_delta <= max_failure_rate_increase_basis_points
        and elapsed_change <= max_elapsed_increase_basis_points
    )
    return PartialLossBenchmarkComparison(
        accepted=accepted,
        baseline_benchmark_sha256=baseline.digest(),
        candidate_benchmark_sha256=candidate.digest(),
        runtime_fingerprint_sha256=baseline.runtime_fingerprint.environment_sha256,
        policy_sha256=hashlib.sha256(_canonical(baseline_policy)).hexdigest(),
        failure_rate_delta_basis_points=failure_delta,
        elapsed_change_basis_points=elapsed_change,
        observed_drop_delta_basis_points=(
            candidate.observed_drop_basis_points - baseline.observed_drop_basis_points
        ),
        max_failure_rate_increase_basis_points=(max_failure_rate_increase_basis_points),
        max_elapsed_increase_basis_points=max_elapsed_increase_basis_points,
    )


def _comparison_policy(evidence: PartialLossBenchmarkEvidence) -> dict[str, int]:
    return {
        "confidence_level_percent": evidence.confidence_level_percent,
        "configured_loss_percent": evidence.configured_loss_percent,
        "probe_attempts": evidence.probe_outcomes.attempts,
        "seed": evidence.seed,
    }


def _rate_basis_points(numerator: int, denominator: int) -> int:
    if denominator < 1 or not 0 <= numerator <= denominator:
        raise ValueError("rate inputs are invalid")
    return (numerator * 10_000 + denominator // 2) // denominator


def _relative_change_basis_points(candidate: int, baseline: int) -> int:
    if baseline < 1 or candidate < 1:
        raise ValueError("relative-change inputs must be positive")
    numerator = (candidate - baseline) * 10_000
    if numerator >= 0:
        return (numerator + baseline // 2) // baseline
    return -((-numerator + baseline // 2) // baseline)


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
