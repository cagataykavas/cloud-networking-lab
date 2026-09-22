from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


class LoadEvidenceError(ValueError):
    """Raised when load-test evidence cannot be evaluated safely."""


@dataclass(frozen=True)
class LoadBalancePolicy:
    expected_backends: tuple[str, ...]
    min_requested: int = 100
    min_success_lower_bound: float = 0.95
    confidence_z: float = 1.96
    max_backend_share_excess: float = 0.20
    max_p95_ms: float = 250.0
    allow_unexpected_backends: bool = False

    def __post_init__(self) -> None:
        if not self.expected_backends or any(not item.strip() for item in self.expected_backends):
            raise ValueError("expected_backends must contain non-empty names")
        if len(set(self.expected_backends)) != len(self.expected_backends):
            raise ValueError("expected_backends must be unique")
        if isinstance(self.min_requested, bool) or self.min_requested < 1:
            raise ValueError("min_requested must be a positive integer")
        if not 0.0 <= self.min_success_lower_bound <= 1.0:
            raise ValueError("min_success_lower_bound must be between 0 and 1")
        if not math.isfinite(self.confidence_z) or self.confidence_z <= 0:
            raise ValueError("confidence_z must be positive and finite")
        if not 0.0 <= self.max_backend_share_excess <= 1.0:
            raise ValueError("max_backend_share_excess must be between 0 and 1")
        if not math.isfinite(self.max_p95_ms) or self.max_p95_ms < 0:
            raise ValueError("max_p95_ms must be non-negative and finite")


@dataclass(frozen=True)
class LoadBalanceReport:
    accepted: bool
    requested: int
    succeeded: int
    failed: int
    success_rate: float
    success_rate_lower_bound: float
    p95_ms: float
    expected_backends: tuple[str, ...]
    backend_counts: tuple[tuple[str, int], ...]
    missing_backends: tuple[str, ...]
    unexpected_backends: tuple[str, ...]
    max_backend_share: float
    max_allowed_backend_share: float
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "requested": self.requested,
            "succeeded": self.succeeded,
            "failed": self.failed,
            "success_rate": self.success_rate,
            "success_rate_lower_bound": self.success_rate_lower_bound,
            "p95_ms": self.p95_ms,
            "expected_backends": list(self.expected_backends),
            "backend_counts": dict(self.backend_counts),
            "missing_backends": list(self.missing_backends),
            "unexpected_backends": list(self.unexpected_backends),
            "max_backend_share": self.max_backend_share,
            "max_allowed_backend_share": self.max_allowed_backend_share,
            "reasons": list(self.reasons),
        }


def _non_negative_int(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise LoadEvidenceError(f"{field} must be a non-negative integer")
    return value


def _finite_non_negative(value: Any, field: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise LoadEvidenceError(f"{field} must be numeric")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise LoadEvidenceError(f"{field} must be non-negative and finite")
    return result


def wilson_lower_bound(successes: int, trials: int, z: float = 1.96) -> float:
    if trials <= 0 or successes < 0 or successes > trials:
        raise ValueError("successes and trials must describe a non-empty binomial sample")
    proportion = successes / trials
    denominator = 1 + (z**2 / trials)
    centre = proportion + (z**2 / (2 * trials))
    margin = z * math.sqrt((proportion * (1 - proportion) + z**2 / (4 * trials)) / trials)
    return max(0.0, (centre - margin) / denominator)


def evaluate_load_balance(
    evidence: Mapping[str, Any],
    policy: LoadBalancePolicy,
) -> LoadBalanceReport:
    if not isinstance(evidence, Mapping):
        raise LoadEvidenceError("evidence must be a JSON object")

    requested = _non_negative_int(evidence.get("requested"), "requested")
    succeeded = _non_negative_int(evidence.get("succeeded"), "succeeded")
    failed = _non_negative_int(evidence.get("failed"), "failed")
    if requested == 0:
        raise LoadEvidenceError("requested must be greater than zero")
    if succeeded + failed != requested:
        raise LoadEvidenceError("succeeded + failed must equal requested")

    distribution = evidence.get("backend_distribution")
    if not isinstance(distribution, Mapping):
        raise LoadEvidenceError("backend_distribution must be an object")
    counts: dict[str, int] = {}
    for name, value in distribution.items():
        if not isinstance(name, str) or not name.strip():
            raise LoadEvidenceError("backend_distribution keys must be non-empty strings")
        counts[name] = _non_negative_int(value, f"backend_distribution.{name}")
    if sum(counts.values()) != succeeded:
        raise LoadEvidenceError("backend_distribution counts must sum to succeeded")

    latency = evidence.get("latency_ms")
    if not isinstance(latency, Mapping):
        raise LoadEvidenceError("latency_ms must be an object")
    p95_ms = _finite_non_negative(latency.get("p95"), "latency_ms.p95")

    expected = tuple(sorted(policy.expected_backends))
    expected_set = set(expected)
    missing = tuple(name for name in expected if counts.get(name, 0) == 0)
    unexpected = tuple(sorted(name for name in counts if name not in expected_set))
    assigned = sum(counts.get(name, 0) for name in expected)
    max_share = (
        max((counts.get(name, 0) / assigned for name in expected), default=0.0) if assigned else 0.0
    )
    allowed_share = min(1.0, (1.0 / len(expected)) + policy.max_backend_share_excess)
    success_rate = succeeded / requested
    lower_bound = wilson_lower_bound(succeeded, requested, policy.confidence_z)

    reasons: list[str] = []
    if requested < policy.min_requested:
        reasons.append("insufficient_request_evidence")
    if lower_bound < policy.min_success_lower_bound:
        reasons.append("success_confidence_below_threshold")
    if missing:
        reasons.append("expected_backend_missing")
    if unexpected and not policy.allow_unexpected_backends:
        reasons.append("unexpected_backend_observed")
    if max_share > allowed_share:
        reasons.append("backend_share_exceeded")
    if p95_ms > policy.max_p95_ms:
        reasons.append("p95_latency_exceeded")

    return LoadBalanceReport(
        accepted=not reasons,
        requested=requested,
        succeeded=succeeded,
        failed=failed,
        success_rate=round(success_rate, 6),
        success_rate_lower_bound=round(lower_bound, 6),
        p95_ms=round(p95_ms, 3),
        expected_backends=expected,
        backend_counts=tuple(sorted(counts.items())),
        missing_backends=missing,
        unexpected_backends=unexpected,
        max_backend_share=round(max_share, 6),
        max_allowed_backend_share=round(allowed_share, 6),
        reasons=tuple(reasons),
    )


def _load_json(path: Path | None) -> Mapping[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8") if path else sys.stdin.read()
        payload = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LoadEvidenceError(f"cannot load JSON evidence: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise LoadEvidenceError("evidence must be a JSON object")
    return payload


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Gate reverse-proxy load-balancing evidence")
    parser.add_argument("evidence", nargs="?", type=Path, help="load_demo JSON; defaults to stdin")
    parser.add_argument("--backend", action="append", required=True, dest="backends")
    parser.add_argument("--min-requests", type=int, default=100)
    parser.add_argument("--min-success-lower-bound", type=float, default=0.95)
    parser.add_argument("--max-share-excess", type=float, default=0.20)
    parser.add_argument("--max-p95-ms", type=float, default=250.0)
    parser.add_argument("--allow-unexpected-backends", action="store_true")
    args = parser.parse_args(argv)

    try:
        policy = LoadBalancePolicy(
            expected_backends=tuple(args.backends),
            min_requested=args.min_requests,
            min_success_lower_bound=args.min_success_lower_bound,
            max_backend_share_excess=args.max_share_excess,
            max_p95_ms=args.max_p95_ms,
            allow_unexpected_backends=args.allow_unexpected_backends,
        )
        report = evaluate_load_balance(_load_json(args.evidence), policy)
    except (LoadEvidenceError, ValueError) as exc:
        print(
            json.dumps(
                {"accepted": False, "error": "invalid_load_evidence", "message": str(exc)},
                sort_keys=True,
            )
        )
        return 3

    print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    return 0 if report.accepted else 2


if __name__ == "__main__":
    raise SystemExit(main())
