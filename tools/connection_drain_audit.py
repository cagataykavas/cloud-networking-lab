from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from pathlib import Path
from typing import Any

MAX_ARTIFACT_BYTES = 256 * 1024
MAX_FINDINGS = 128


class ArtifactError(ValueError):
    """The drain evidence or policy cannot be evaluated safely."""


@dataclass(frozen=True, slots=True)
class DrainPolicy:
    min_drain_seconds: int = 30
    max_drain_seconds: int = 900
    max_endpoint_removal_delay_seconds: int = 30
    propagation_grace_seconds: int = 5
    max_sample_gap_seconds: int = 15
    max_terminal_sample_lag_seconds: int = 10
    max_failed_requests: int = 0
    max_concurrent_drains: int = 1
    max_backends: int = 100
    max_samples_per_backend: int = 1000
    max_artifact_age_seconds: int = 3600
    max_future_skew_seconds: int = 30

    def __post_init__(self) -> None:
        positive = (
            "min_drain_seconds",
            "max_drain_seconds",
            "max_endpoint_removal_delay_seconds",
            "max_sample_gap_seconds",
            "max_terminal_sample_lag_seconds",
            "max_concurrent_drains",
            "max_backends",
            "max_samples_per_backend",
            "max_artifact_age_seconds",
        )
        nonnegative = (
            "propagation_grace_seconds",
            "max_failed_requests",
            "max_future_skew_seconds",
        )
        for name in positive:
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ArtifactError(f"{name} must be a positive integer")
        for name in nonnegative:
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ArtifactError(f"{name} must be a non-negative integer")
        if self.max_drain_seconds < self.min_drain_seconds:
            raise ArtifactError("max_drain_seconds must cover min_drain_seconds")


@dataclass(frozen=True, slots=True)
class ConnectionSample:
    observed_at: datetime
    active_connections: int
    new_connections: int
    in_flight_requests: int
    failed_requests: int


@dataclass(frozen=True, slots=True)
class BackendDrain:
    backend_id: str
    termination_notice_at: datetime
    replacement_ready_at: datetime
    readiness_withdrawn_at: datetime
    endpoint_removed_at: datetime
    terminated_at: datetime
    samples: tuple[ConnectionSample, ...]


@dataclass(frozen=True, slots=True)
class DrainArtifact:
    schema_version: int
    deployment_id: str
    collected_at: datetime
    backends: tuple[BackendDrain, ...]


@dataclass(frozen=True, slots=True, order=True)
class Finding:
    code: str
    backend_ref: str
    sample_index: int | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"backend_ref": self.backend_ref, "code": self.code}
        if self.sample_index is not None:
            result["sample_index"] = self.sample_index
        return result


@dataclass(frozen=True, slots=True)
class DrainReport:
    accepted: bool
    artifact_sha256: str
    deployment_ref: str
    policy_sha256: str
    evaluated_at: str
    backend_count: int
    sample_count: int
    peak_concurrent_drains: int
    findings: tuple[Finding, ...]
    findings_truncated: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "artifact_sha256": self.artifact_sha256,
            "backend_count": self.backend_count,
            "deployment_ref": self.deployment_ref,
            "evaluated_at": self.evaluated_at,
            "finding_count": len(self.findings),
            "findings": [finding.to_dict() for finding in self.findings],
            "findings_truncated": self.findings_truncated,
            "peak_concurrent_drains": self.peak_concurrent_drains,
            "policy_sha256": self.policy_sha256,
            "sample_count": self.sample_count,
        }


def load_artifact_bytes(raw: bytes) -> DrainArtifact:
    if not raw or len(raw) > MAX_ARTIFACT_BYTES:
        raise ArtifactError("artifact must be non-empty and at most 256 KiB")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ArtifactError(f"duplicate JSON field: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ArtifactError(f"non-finite JSON number: {value}")

    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=reject_constant)
    except UnicodeDecodeError as exc:
        raise ArtifactError("artifact must be UTF-8 JSON") from exc
    except json.JSONDecodeError as exc:
        raise ArtifactError("artifact must be valid JSON") from exc
    return parse_artifact(value)


def parse_artifact(value: Any) -> DrainArtifact:
    root = _object(value, "artifact")
    _keys(root, {"schema_version", "deployment_id", "collected_at", "backends"}, "artifact")
    schema_version = _integer(root["schema_version"], "schema_version", minimum=1, maximum=1)
    deployment_id = _label(root["deployment_id"], "deployment_id")
    collected_at = _timestamp(root["collected_at"], "collected_at")
    raw_backends = _list(root["backends"], "backends")
    if not raw_backends:
        raise ArtifactError("backends must not be empty")
    backends = tuple(_parse_backend(item, index) for index, item in enumerate(raw_backends))
    ids = [backend.backend_id for backend in backends]
    if len(ids) != len(set(ids)):
        raise ArtifactError("backend_id values must be unique")
    return DrainArtifact(schema_version, deployment_id, collected_at, backends)


def audit_connection_drains(
    artifact: DrainArtifact,
    policy: DrainPolicy | None = None,
    *,
    now: datetime | None = None,
) -> DrainReport:
    policy = policy or DrainPolicy()
    evaluated_at = _as_utc(now or datetime.now(UTC), "now")
    findings: list[Finding] = []
    if len(artifact.backends) > policy.max_backends:
        findings.append(Finding("BACKEND_LIMIT_EXCEEDED", "artifact"))
    if artifact.collected_at > evaluated_at + timedelta(seconds=policy.max_future_skew_seconds):
        findings.append(Finding("COLLECTED_AT_IN_FUTURE", "artifact"))
    if evaluated_at - artifact.collected_at > timedelta(seconds=policy.max_artifact_age_seconds):
        findings.append(Finding("ARTIFACT_STALE", "artifact"))

    sample_count = 0
    for backend in sorted(artifact.backends, key=lambda item: item.backend_id):
        sample_count += len(backend.samples)
        _audit_backend(backend, artifact.collected_at, policy, findings)

    peak = _peak_concurrent_drains(artifact.backends)
    if peak > policy.max_concurrent_drains:
        findings.append(Finding("CONCURRENT_DRAIN_LIMIT_EXCEEDED", "artifact"))

    bounded = tuple(sorted(findings)[:MAX_FINDINGS])
    canonical_artifact = _canonical_artifact(artifact)
    return DrainReport(
        accepted=not bounded,
        artifact_sha256=_digest(canonical_artifact),
        deployment_ref=_ref("dep", artifact.deployment_id),
        policy_sha256=_digest(_policy_dict(policy)),
        evaluated_at=evaluated_at.isoformat(),
        backend_count=len(artifact.backends),
        sample_count=sample_count,
        peak_concurrent_drains=peak,
        findings=bounded,
        findings_truncated=len(findings) > MAX_FINDINGS,
    )


def _parse_backend(value: Any, index: int) -> BackendDrain:
    context = f"backends[{index}]"
    item = _object(value, context)
    _keys(
        item,
        {
            "backend_id",
            "termination_notice_at",
            "replacement_ready_at",
            "readiness_withdrawn_at",
            "endpoint_removed_at",
            "terminated_at",
            "samples",
        },
        context,
    )
    raw_samples = _list(item["samples"], f"{context}.samples")
    if not raw_samples:
        raise ArtifactError(f"{context}.samples must not be empty")
    samples = tuple(
        _parse_sample(sample, f"{context}.samples[{sample_index}]")
        for sample_index, sample in enumerate(raw_samples)
    )
    return BackendDrain(
        backend_id=_label(item["backend_id"], f"{context}.backend_id"),
        termination_notice_at=_timestamp(
            item["termination_notice_at"], f"{context}.termination_notice_at"
        ),
        replacement_ready_at=_timestamp(
            item["replacement_ready_at"], f"{context}.replacement_ready_at"
        ),
        readiness_withdrawn_at=_timestamp(
            item["readiness_withdrawn_at"], f"{context}.readiness_withdrawn_at"
        ),
        endpoint_removed_at=_timestamp(
            item["endpoint_removed_at"], f"{context}.endpoint_removed_at"
        ),
        terminated_at=_timestamp(item["terminated_at"], f"{context}.terminated_at"),
        samples=samples,
    )


def _parse_sample(value: Any, context: str) -> ConnectionSample:
    item = _object(value, context)
    _keys(
        item,
        {
            "observed_at",
            "active_connections",
            "new_connections",
            "in_flight_requests",
            "failed_requests",
        },
        context,
    )
    return ConnectionSample(
        observed_at=_timestamp(item["observed_at"], f"{context}.observed_at"),
        active_connections=_integer(item["active_connections"], f"{context}.active_connections"),
        new_connections=_integer(item["new_connections"], f"{context}.new_connections"),
        in_flight_requests=_integer(item["in_flight_requests"], f"{context}.in_flight_requests"),
        failed_requests=_integer(item["failed_requests"], f"{context}.failed_requests"),
    )


def _audit_backend(
    backend: BackendDrain,
    collected_at: datetime,
    policy: DrainPolicy,
    findings: list[Finding],
) -> None:
    ref = _ref("bkd", backend.backend_id)
    if len(backend.samples) > policy.max_samples_per_backend:
        findings.append(Finding("SAMPLE_LIMIT_EXCEEDED", ref))
        return
    if backend.termination_notice_at > backend.readiness_withdrawn_at:
        findings.append(Finding("READINESS_PRECEDES_TERMINATION_NOTICE", ref))
    if backend.replacement_ready_at > backend.readiness_withdrawn_at:
        findings.append(Finding("REPLACEMENT_NOT_READY", ref))
    if backend.readiness_withdrawn_at > backend.endpoint_removed_at:
        findings.append(Finding("ENDPOINT_REMOVED_BEFORE_READINESS", ref))
    if backend.endpoint_removed_at > backend.terminated_at:
        findings.append(Finding("TERMINATED_BEFORE_ENDPOINT_REMOVAL", ref))
    if backend.terminated_at > collected_at:
        findings.append(Finding("TERMINATION_AFTER_COLLECTION", ref))

    drain_seconds = (backend.terminated_at - backend.readiness_withdrawn_at).total_seconds()
    if drain_seconds < policy.min_drain_seconds:
        findings.append(Finding("DRAIN_WINDOW_TOO_SHORT", ref))
    if drain_seconds > policy.max_drain_seconds:
        findings.append(Finding("DRAIN_WINDOW_TOO_LONG", ref))
    endpoint_delay = (backend.endpoint_removed_at - backend.readiness_withdrawn_at).total_seconds()
    if endpoint_delay > policy.max_endpoint_removal_delay_seconds:
        findings.append(Finding("ENDPOINT_REMOVAL_TOO_SLOW", ref))

    times = [sample.observed_at for sample in backend.samples]
    for index in range(1, len(times)):
        if times[index] <= times[index - 1]:
            findings.append(Finding("SAMPLES_NOT_STRICTLY_ORDERED", ref, index))
            break
    if any(timestamp > collected_at for timestamp in times):
        findings.append(Finding("SAMPLE_AFTER_COLLECTION", ref))
    if any(timestamp > backend.terminated_at for timestamp in times):
        findings.append(Finding("SAMPLE_AFTER_TERMINATION", ref))
    if times[0] > backend.readiness_withdrawn_at:
        findings.append(Finding("PRE_DRAIN_SAMPLE_MISSING", ref))

    timeline = [backend.termination_notice_at]
    timeline.extend(
        time for time in times if backend.termination_notice_at <= time <= backend.terminated_at
    )
    timeline.append(backend.terminated_at)
    if any(
        (right - left).total_seconds() > policy.max_sample_gap_seconds
        for left, right in pairwise(timeline)
    ):
        findings.append(Finding("SAMPLE_GAP_EXCEEDED", ref))

    terminal = backend.samples[-1]
    terminal_lag = (backend.terminated_at - terminal.observed_at).total_seconds()
    if terminal.observed_at < backend.endpoint_removed_at or terminal_lag < 0:
        findings.append(Finding("TERMINAL_SAMPLE_OUTSIDE_DRAIN", ref))
    elif terminal_lag > policy.max_terminal_sample_lag_seconds:
        findings.append(Finding("TERMINAL_SAMPLE_TOO_OLD", ref))
    if terminal.active_connections != 0:
        findings.append(Finding("ACTIVE_CONNECTIONS_AT_TERMINATION", ref))
    if terminal.in_flight_requests != 0:
        findings.append(Finding("IN_FLIGHT_REQUESTS_AT_TERMINATION", ref))

    cutoff = backend.endpoint_removed_at + timedelta(seconds=policy.propagation_grace_seconds)
    for index, sample in enumerate(backend.samples):
        if sample.observed_at > cutoff and sample.new_connections > 0:
            findings.append(Finding("LATE_NEW_CONNECTIONS", ref, index))
        if index:
            growth = sample.active_connections - backend.samples[index - 1].active_connections
            if growth > sample.new_connections:
                findings.append(Finding("CONNECTION_COUNTER_INCONSISTENT", ref, index))
    if sum(sample.failed_requests for sample in backend.samples) > policy.max_failed_requests:
        findings.append(Finding("FAILED_REQUEST_BUDGET_EXCEEDED", ref))


def _peak_concurrent_drains(backends: tuple[BackendDrain, ...]) -> int:
    points: list[tuple[datetime, int]] = []
    for backend in backends:
        points.append((backend.readiness_withdrawn_at, 1))
        points.append((backend.terminated_at, -1))
    active = peak = 0
    for _, change in sorted(points, key=lambda item: (item[0], item[1])):
        active += change
        peak = max(peak, active)
    return peak


def _canonical_artifact(artifact: DrainArtifact) -> dict[str, Any]:
    return {
        "backends": [
            {
                "backend_ref": _ref("bkd", backend.backend_id),
                "endpoint_removed_at": backend.endpoint_removed_at.isoformat(),
                "readiness_withdrawn_at": backend.readiness_withdrawn_at.isoformat(),
                "replacement_ready_at": backend.replacement_ready_at.isoformat(),
                "samples": [
                    {
                        "active_connections": sample.active_connections,
                        "failed_requests": sample.failed_requests,
                        "in_flight_requests": sample.in_flight_requests,
                        "new_connections": sample.new_connections,
                        "observed_at": sample.observed_at.isoformat(),
                    }
                    for sample in backend.samples
                ],
                "terminated_at": backend.terminated_at.isoformat(),
                "termination_notice_at": backend.termination_notice_at.isoformat(),
            }
            for backend in sorted(artifact.backends, key=lambda item: item.backend_id)
        ],
        "collected_at": artifact.collected_at.isoformat(),
        "deployment_ref": _ref("dep", artifact.deployment_id),
        "schema_version": artifact.schema_version,
    }


def _policy_dict(policy: DrainPolicy) -> dict[str, int]:
    return {name: getattr(policy, name) for name in DrainPolicy.__dataclass_fields__}


def _object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ArtifactError(f"{name} must be an object")
    return value


def _list(value: Any, name: str) -> list[Any]:
    if not isinstance(value, list):
        raise ArtifactError(f"{name} must be an array")
    return value


def _keys(value: dict[str, Any], expected: set[str], name: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        raise ArtifactError(f"{name} fields invalid; missing={missing}, unknown={unknown}")


def _integer(value: Any, name: str, *, minimum: int = 0, maximum: int | None = None) -> int:
    if type(value) is not int or value < minimum or (maximum is not None and value > maximum):
        raise ArtifactError(f"{name} must be an integer in the allowed range")
    return value


def _label(value: Any, name: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 200
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ArtifactError(f"{name} must be 1-200 printable characters")
    return value


def _timestamp(value: Any, name: str) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise ArtifactError(f"{name} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ArtifactError(f"{name} must be an ISO-8601 timestamp") from exc
    return _as_utc(parsed, name)


def _as_utc(value: datetime, name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ArtifactError(f"{name} must be timezone-aware")
    return value.astimezone(UTC)


def _ref(prefix: str, value: str) -> str:
    return f"{prefix}_{hashlib.sha256(value.encode()).hexdigest()[:16]}"


def _digest(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit load-balancer connection draining evidence")
    parser.add_argument("artifact", type=Path, nargs="?", help="JSON artifact; omit to read stdin")
    parser.add_argument("--now", help="timezone-aware evaluation timestamp")
    parser.add_argument("--min-drain-seconds", type=int, default=30)
    parser.add_argument("--max-drain-seconds", type=int, default=900)
    parser.add_argument("--max-concurrent-drains", type=int, default=1)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        raw = (
            args.artifact.read_bytes()
            if args.artifact
            else sys.stdin.buffer.read(MAX_ARTIFACT_BYTES + 1)
        )
        artifact = load_artifact_bytes(raw)
        policy = DrainPolicy(
            min_drain_seconds=args.min_drain_seconds,
            max_drain_seconds=args.max_drain_seconds,
            max_concurrent_drains=args.max_concurrent_drains,
        )
        evaluated_at = _timestamp(args.now, "now") if args.now else datetime.now(UTC)
        report = audit_connection_drains(artifact, policy, now=evaluated_at)
    except (ArtifactError, OSError) as exc:
        print(json.dumps({"accepted": False, "error": str(exc), "status": "malformed"}))
        return 3
    print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    return 0 if report.accepted else 2


if __name__ == "__main__":
    raise SystemExit(main())
