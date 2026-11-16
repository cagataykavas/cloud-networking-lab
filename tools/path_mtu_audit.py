from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


MAX_POLICY_BYTES = 1024 * 1024
MAX_SEGMENTS = 128
_SEGMENT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,63}\Z")
_FAMILY_FLOORS = {"ipv4": 576, "ipv6": 1280, "dual_stack": 1280}


class PolicyError(ValueError):
    """Raised when a path-MTU policy is ambiguous or unsafe to evaluate."""


@dataclass(frozen=True)
class Segment:
    name: str
    link_mtu: int
    encapsulation_overhead: int
    pmtud_signals_allowed: bool

    @property
    def inner_mtu_budget(self) -> int:
        return self.link_mtu - self.encapsulation_overhead


@dataclass(frozen=True)
class PathMtuPolicy:
    ip_family: str
    required_ip_mtu: int
    segments: tuple[Segment, ...]


@dataclass(frozen=True)
class SegmentBudget:
    name: str
    link_mtu: int
    encapsulation_overhead: int
    inner_mtu_budget: int


@dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    segment: str | None
    message: str


@dataclass(frozen=True)
class AuditReport:
    admitted: bool
    ip_family: str
    required_ip_mtu: int
    effective_ip_mtu: int
    bottleneck_segments: tuple[str, ...]
    recommended_tcp_mss: dict[str, int]
    segment_budgets: tuple[SegmentBudget, ...]
    findings: tuple[Finding, ...]


def _require_exact_keys(
    value: dict[str, Any], *, required: set[str], context: str
) -> None:
    actual = set(value)
    missing = sorted(required - actual)
    unknown = sorted(actual - required)
    if missing:
        raise PolicyError(f"{context} is missing fields: {', '.join(missing)}")
    if unknown:
        raise PolicyError(f"{context} has unknown fields: {', '.join(unknown)}")


def _require_int(value: Any, *, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PolicyError(f"{field} must be an integer")
    if not minimum <= value <= maximum:
        raise PolicyError(f"{field} must be between {minimum} and {maximum}")
    return value


def parse_policy(payload: Any) -> PathMtuPolicy:
    if not isinstance(payload, dict):
        raise PolicyError("policy must be a JSON object")
    _require_exact_keys(
        payload,
        required={"ip_family", "required_ip_mtu", "segments"},
        context="policy",
    )

    family = payload["ip_family"]
    if family not in _FAMILY_FLOORS:
        choices = ", ".join(sorted(_FAMILY_FLOORS))
        raise PolicyError(f"ip_family must be one of: {choices}")
    required_mtu = _require_int(
        payload["required_ip_mtu"],
        field="required_ip_mtu",
        minimum=_FAMILY_FLOORS[family],
        maximum=65535,
    )

    raw_segments = payload["segments"]
    if not isinstance(raw_segments, list) or not raw_segments:
        raise PolicyError("segments must be a non-empty array")
    if len(raw_segments) > MAX_SEGMENTS:
        raise PolicyError(f"segments cannot contain more than {MAX_SEGMENTS} entries")

    segments: list[Segment] = []
    seen_names: set[str] = set()
    for index, raw_segment in enumerate(raw_segments):
        context = f"segments[{index}]"
        if not isinstance(raw_segment, dict):
            raise PolicyError(f"{context} must be an object")
        _require_exact_keys(
            raw_segment,
            required={
                "name",
                "link_mtu",
                "encapsulation_overhead",
                "pmtud_signals_allowed",
            },
            context=context,
        )
        name = raw_segment["name"]
        if not isinstance(name, str) or not _SEGMENT_NAME.fullmatch(name):
            raise PolicyError(
                f"{context}.name must be a safe 1-64 character identifier"
            )
        if name in seen_names:
            raise PolicyError(f"duplicate segment name: {name}")
        seen_names.add(name)

        link_mtu = _require_int(
            raw_segment["link_mtu"],
            field=f"{context}.link_mtu",
            minimum=576,
            maximum=65535,
        )
        overhead = _require_int(
            raw_segment["encapsulation_overhead"],
            field=f"{context}.encapsulation_overhead",
            minimum=0,
            maximum=4096,
        )
        if overhead >= link_mtu:
            raise PolicyError(
                f"{context}.encapsulation_overhead must be less than link_mtu"
            )
        pmtud_allowed = raw_segment["pmtud_signals_allowed"]
        if not isinstance(pmtud_allowed, bool):
            raise PolicyError(f"{context}.pmtud_signals_allowed must be a boolean")

        segments.append(Segment(name, link_mtu, overhead, pmtud_allowed))

    return PathMtuPolicy(family, required_mtu, tuple(segments))


def audit_path_mtu(policy: PathMtuPolicy) -> AuditReport:
    budgets = tuple(
        SegmentBudget(
            name=segment.name,
            link_mtu=segment.link_mtu,
            encapsulation_overhead=segment.encapsulation_overhead,
            inner_mtu_budget=segment.inner_mtu_budget,
        )
        for segment in policy.segments
    )
    effective_mtu = min(segment.inner_mtu_budget for segment in policy.segments)
    bottlenecks = tuple(
        segment.name
        for segment in policy.segments
        if segment.inner_mtu_budget == effective_mtu
    )
    findings: list[Finding] = []

    floor = _FAMILY_FLOORS[policy.ip_family]
    if effective_mtu < floor:
        findings.append(
            Finding(
                severity="error",
                code="protocol_floor_violation",
                segment=",".join(bottlenecks),
                message=(
                    f"effective MTU {effective_mtu} is below the {policy.ip_family} "
                    f"policy floor of {floor} bytes"
                ),
            )
        )
    if policy.required_ip_mtu > effective_mtu:
        findings.append(
            Finding(
                severity="error",
                code="required_mtu_exceeds_path_budget",
                segment=",".join(bottlenecks),
                message=(
                    f"required MTU {policy.required_ip_mtu} exceeds the effective "
                    f"path budget of {effective_mtu} bytes"
                ),
            )
        )
    for segment in policy.segments:
        if not segment.pmtud_signals_allowed:
            findings.append(
                Finding(
                    severity="error",
                    code="pmtud_signal_blocked",
                    segment=segment.name,
                    message=(
                        "ICMP Packet Too Big / Fragmentation Needed feedback is not allowed; "
                        "unexpected MTU reductions can become black holes"
                    ),
                )
            )

    tcp_mss: dict[str, int] = {}
    if policy.ip_family in {"ipv4", "dual_stack"}:
        tcp_mss["ipv4"] = max(0, effective_mtu - 40)
    if policy.ip_family in {"ipv6", "dual_stack"}:
        tcp_mss["ipv6"] = max(0, effective_mtu - 60)

    return AuditReport(
        admitted=not any(finding.severity == "error" for finding in findings),
        ip_family=policy.ip_family,
        required_ip_mtu=policy.required_ip_mtu,
        effective_ip_mtu=effective_mtu,
        bottleneck_segments=bottlenecks,
        recommended_tcp_mss=tcp_mss,
        segment_budgets=budgets,
        findings=tuple(findings),
    )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def load_policy(path: Path) -> PathMtuPolicy:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise PolicyError(f"cannot inspect policy file: {exc}") from exc
    if size > MAX_POLICY_BYTES:
        raise PolicyError(f"policy file exceeds {MAX_POLICY_BYTES} bytes")
    try:
        raw = path.read_text(encoding="utf-8")
        payload = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                PolicyError(f"non-finite JSON number: {value}")
            ),
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PolicyError(f"cannot read policy JSON: {exc}") from exc
    return parse_policy(payload)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Audit an overlay path's MTU, encapsulation and PMTUD admission policy."
    )
    parser.add_argument("policy", type=Path, help="path to the JSON policy")
    args = parser.parse_args(argv)
    try:
        report = audit_path_mtu(load_policy(args.policy))
    except PolicyError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 1
    print(json.dumps(asdict(report), indent=2, sort_keys=True))
    return 0 if report.admitted else 2


if __name__ == "__main__":
    raise SystemExit(main())
