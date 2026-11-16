from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from ipaddress import IPv4Network, IPv6Network, ip_network
from typing import Iterable, TypeVar


SCHEMA_VERSION = "route-origin-admission/v1"
Network = IPv4Network | IPv6Network
T = TypeVar("T")


class RouteAdmissionError(ValueError):
    """Raised when route evidence cannot be audited safely."""


@dataclass(frozen=True)
class OriginAuthorization:
    prefix: str
    origin_asn: int
    max_prefix_length: int


@dataclass(frozen=True)
class RouteAnnouncement:
    prefix: str
    origin_asn: int
    as_path: tuple[int, ...]


@dataclass(frozen=True)
class RoutePolicy:
    local_asn: int
    max_as_path_length: int = 64
    allow_default_route: bool = False
    max_announcements: int = 10_000
    max_authorizations: int = 10_000


@dataclass(frozen=True)
class RouteResult:
    prefix: str
    origin_asn: int
    as_path: tuple[int, ...]
    accepted: bool
    findings: tuple[str, ...]
    matched_authorization: str | None


@dataclass(frozen=True)
class FindingCount:
    code: str
    count: int


@dataclass(frozen=True)
class RouteAdmissionReport:
    schema_version: str
    accepted: bool
    evidence_sha256: str
    announcement_count: int
    accepted_count: int
    rejected_count: int
    finding_counts: tuple[FindingCount, ...]
    routes: tuple[RouteResult, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _bounded(values: Iterable[T], limit: int, field: str) -> list[T]:
    rows: list[T] = []
    for value in values:
        if len(rows) >= limit:
            raise RouteAdmissionError(f"{field} exceeds the configured record budget")
        rows.append(value)
    return rows


def _asn(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise RouteAdmissionError(f"{field} must be an integer ASN")
    if not 1 <= value <= 4_294_967_294:
        raise RouteAdmissionError(f"{field} is outside the usable ASN range")
    return value


def _prefix(value: object, field: str) -> Network:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise RouteAdmissionError(f"{field} must be a bounded CIDR string")
    try:
        return ip_network(value, strict=True)
    except ValueError as error:
        raise RouteAdmissionError(
            f"{field} must be a canonical IPv4 or IPv6 prefix"
        ) from error


def _policy(policy: RoutePolicy) -> None:
    _asn(policy.local_asn, "policy.local_asn")
    if isinstance(policy.max_as_path_length, bool) or not isinstance(
        policy.max_as_path_length, int
    ):
        raise RouteAdmissionError("policy.max_as_path_length must be an integer")
    if not 1 <= policy.max_as_path_length <= 256:
        raise RouteAdmissionError("policy.max_as_path_length must be in [1, 256]")
    if not isinstance(policy.allow_default_route, bool):
        raise RouteAdmissionError("policy.allow_default_route must be a boolean")
    for field, value in (
        ("max_announcements", policy.max_announcements),
        ("max_authorizations", policy.max_authorizations),
    ):
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 1 <= value <= 100_000
        ):
            raise RouteAdmissionError(
                f"policy.{field} must be an integer in [1, 100000]"
            )


def _network_key(network: Network) -> tuple[int, int, int]:
    return network.version, int(network.network_address), network.prefixlen


def audit_route_announcements(
    announcements: Iterable[RouteAnnouncement],
    authorizations: Iterable[OriginAuthorization],
    policy: RoutePolicy,
) -> RouteAdmissionReport:
    """Audit BGP-style route evidence against reviewed prefix-origin authorizations.

    Authorization semantics mirror route-origin validation: a route is authorized
    when a covering prefix names the same origin ASN and permits the announced
    prefix length. AS-path and local loop checks are evaluated independently.
    """

    _policy(policy)
    announcement_rows = _bounded(
        announcements, policy.max_announcements, "announcements"
    )
    authorization_rows = _bounded(
        authorizations, policy.max_authorizations, "authorizations"
    )
    if not announcement_rows:
        raise RouteAdmissionError("announcements must not be empty")
    if not authorization_rows:
        raise RouteAdmissionError("authorizations must not be empty")

    validated_authorizations: list[tuple[OriginAuthorization, Network]] = []
    authorization_keys: set[tuple[str, int]] = set()
    for index, authorization in enumerate(authorization_rows):
        network = _prefix(authorization.prefix, f"authorizations[{index}].prefix")
        origin = _asn(authorization.origin_asn, f"authorizations[{index}].origin_asn")
        maximum = authorization.max_prefix_length
        if isinstance(maximum, bool) or not isinstance(maximum, int):
            raise RouteAdmissionError(
                f"authorizations[{index}].max_prefix_length must be an integer"
            )
        if not network.prefixlen <= maximum <= network.max_prefixlen:
            raise RouteAdmissionError(
                f"authorizations[{index}].max_prefix_length is outside the prefix family"
            )
        key = (str(network), origin)
        if key in authorization_keys:
            raise RouteAdmissionError(
                "authorizations contain a duplicate prefix-origin pair"
            )
        authorization_keys.add(key)
        validated_authorizations.append((authorization, network))

    results: list[RouteResult] = []
    canonical_announcements: list[dict[str, object]] = []
    announcement_keys: set[tuple[str, int, tuple[int, ...]]] = set()
    for index, announcement in enumerate(announcement_rows):
        network = _prefix(announcement.prefix, f"announcements[{index}].prefix")
        origin = _asn(announcement.origin_asn, f"announcements[{index}].origin_asn")
        if (
            not isinstance(announcement.as_path, (tuple, list))
            or not announcement.as_path
        ):
            raise RouteAdmissionError(
                f"announcements[{index}].as_path must be non-empty"
            )
        if len(announcement.as_path) > 512:
            raise RouteAdmissionError(
                f"announcements[{index}].as_path exceeds 512 ASNs"
            )
        path = tuple(
            _asn(value, f"announcements[{index}].as_path[{position}]")
            for position, value in enumerate(announcement.as_path)
        )
        key = (str(network), origin, path)
        if key in announcement_keys:
            raise RouteAdmissionError("announcements contain duplicate route evidence")
        announcement_keys.add(key)

        findings: list[str] = []
        if network.prefixlen == 0 and not policy.allow_default_route:
            findings.append("default_route_not_allowed")
        if len(path) > policy.max_as_path_length:
            findings.append("as_path_too_long")
        if policy.local_asn in path:
            findings.append("local_asn_loop")
        if path[-1] != origin:
            findings.append("as_path_origin_mismatch")

        covering = [
            (authorization, authorized_network)
            for authorization, authorized_network in validated_authorizations
            if authorized_network.version == network.version
            and network.subnet_of(authorized_network)
        ]
        valid = [
            (authorization, authorized_network)
            for authorization, authorized_network in covering
            if authorization.origin_asn == origin
            and network.prefixlen <= authorization.max_prefix_length
        ]
        matched: str | None = None
        if valid:
            _, matched_network = max(valid, key=lambda item: item[1].prefixlen)
            matched = str(matched_network)
        elif not covering:
            findings.append("unregistered_prefix")
        elif any(authorization.origin_asn == origin for authorization, _ in covering):
            findings.append("prefix_too_specific")
        else:
            findings.append("unauthorized_origin")

        ordered_findings = tuple(findings)
        results.append(
            RouteResult(
                prefix=str(network),
                origin_asn=origin,
                as_path=path,
                accepted=not ordered_findings,
                findings=ordered_findings,
                matched_authorization=matched,
            )
        )
        canonical_announcements.append(
            {"prefix": str(network), "origin_asn": origin, "as_path": list(path)}
        )

    results.sort(
        key=lambda result: (
            *_network_key(ip_network(result.prefix)),
            result.origin_asn,
            result.as_path,
        )
    )
    finding_totals: dict[str, int] = {}
    for result in results:
        for finding in result.findings:
            finding_totals[finding] = finding_totals.get(finding, 0) + 1

    canonical_authorizations = sorted(
        (
            {
                "prefix": str(network),
                "origin_asn": authorization.origin_asn,
                "max_prefix_length": authorization.max_prefix_length,
            }
            for authorization, network in validated_authorizations
        ),
        key=lambda row: (row["prefix"], row["origin_asn"]),
    )
    canonical = {
        "schema_version": SCHEMA_VERSION,
        "policy": asdict(policy),
        "authorizations": canonical_authorizations,
        "announcements": sorted(
            canonical_announcements,
            key=lambda row: (row["prefix"], row["origin_asn"], row["as_path"]),
        ),
    }
    evidence_sha256 = hashlib.sha256(
        json.dumps(
            canonical, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    ).hexdigest()
    accepted_count = sum(result.accepted for result in results)
    return RouteAdmissionReport(
        schema_version=SCHEMA_VERSION,
        accepted=accepted_count == len(results),
        evidence_sha256=evidence_sha256,
        announcement_count=len(results),
        accepted_count=accepted_count,
        rejected_count=len(results) - accepted_count,
        finding_counts=tuple(
            FindingCount(code=code, count=count)
            for code, count in sorted(finding_totals.items())
        ),
        routes=tuple(results),
    )
