#!/usr/bin/env python3
"""Fail-closed admission gate for staged mTLS certificate rotations.

The gate consumes bounded, normalized observations from a trusted collector.  It
does not parse private keys or initiate network traffic; see the accompanying
operational guide for the trust boundary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from itertools import pairwise
from pathlib import Path
from typing import Any, NoReturn

MAX_INPUT_BYTES = 131_072
MAX_CERTIFICATES = 16
MAX_IDENTITIES = 64
MAX_OBSERVATIONS = 4_096
MAX_STRING = 512
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$")
PHASE_NAMES = (
    "dual_trust_old_leaf",
    "dual_trust_new_leaf",
    "new_trust_only",
)
TOP_KEYS = {
    "schema_version",
    "rotation_id",
    "service_identity",
    "policy_version",
    "collected_at",
    "policy",
    "certificate_refs",
    "certificates",
    "phases",
}
POLICY_KEYS = {
    "required_clients",
    "required_instances",
    "min_overlap_seconds",
    "min_remaining_validity_seconds",
    "max_evidence_age_seconds",
    "max_future_skew_seconds",
    "min_successes_per_pair",
    "max_failure_rate",
}
REF_KEYS = {"old_ca", "new_ca", "old_leaf", "new_leaf"}
CERT_KEYS = {
    "fingerprint_sha256",
    "kind",
    "issuer_fingerprint_sha256",
    "not_before",
    "not_after",
    "public_key_algorithm",
    "public_key_bits",
    "san_identities",
    "extended_key_usage",
}
PHASE_KEYS = {
    "name",
    "started_at",
    "completed_at",
    "trusted_ca_fingerprints",
    "presentations",
    "observations",
}
PRESENTATION_KEYS = {"instance_id", "leaf_fingerprint_sha256"}
OBSERVATION_KEYS = {
    "client_id",
    "instance_id",
    "trusted_ca_fingerprints",
    "presented_leaf_fingerprint_sha256",
    "verified_ca_fingerprint_sha256",
    "attempts",
    "successes",
    "failure_codes",
}


class ArtifactError(ValueError):
    """The evidence artifact is malformed or exceeds a resource budget."""


@dataclass(frozen=True)
class Finding:
    code: str
    phase: str | None = None

    def as_dict(self) -> dict[str, str]:
        result = {"code": self.code}
        if self.phase is not None:
            result["phase"] = self.phase
        return result


def _reject(message: str) -> NoReturn:
    raise ArtifactError(message)


def _object_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _reject(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def load_artifact(path: Path) -> dict[str, Any]:
    """Read a bounded JSON object while rejecting duplicate/non-finite values."""

    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ArtifactError("artifact cannot be read") from exc
    if not raw or len(raw) > MAX_INPUT_BYTES:
        _reject("artifact size is outside the allowed range")
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_object_no_duplicates,
            parse_constant=lambda token: _reject(f"non-finite number: {token}"),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArtifactError("artifact is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        _reject("artifact root must be an object")
    return value


def _mapping(value: Any, name: str, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        _reject(f"{name} must be an object")
    unknown = set(value) - keys
    missing = keys - set(value)
    if unknown or missing:
        _reject(f"{name} has unknown or missing members")
    return value


def _sequence(value: Any, name: str, *, minimum: int = 0, maximum: int) -> list[Any]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        _reject(f"{name} must contain {minimum}..{maximum} items")
    return value


def _string(value: Any, name: str, *, identifier: bool = False) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_STRING:
        _reject(f"{name} must be a non-empty bounded string")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        _reject(f"{name} contains a control character")
    if identifier and not IDENTIFIER_RE.fullmatch(value):
        _reject(f"{name} is not a valid identifier")
    return value


def _fingerprint(value: Any, name: str) -> str:
    result = _string(value, name)
    if not SHA256_RE.fullmatch(result):
        _reject(f"{name} must be lowercase SHA-256 hex")
    return result


def _integer(value: Any, name: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        _reject(f"{name} must be an integer in {minimum}..{maximum}")
    return value


def _number(value: Any, name: str, *, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _reject(f"{name} must be numeric")
    result = float(value)
    if not math.isfinite(result) or not minimum <= result <= maximum:
        _reject(f"{name} is outside the allowed range")
    return result


def _timestamp(value: Any, name: str) -> datetime:
    text = _string(value, name)
    if not text.endswith("Z"):
        _reject(f"{name} must use UTC Z notation")
    try:
        result = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ArtifactError(f"{name} is not an RFC 3339 timestamp") from exc
    if result.tzinfo is None or result.utcoffset() != UTC.utcoffset(result):
        _reject(f"{name} must be UTC")
    return result


def _unique_strings(value: Any, name: str, *, maximum: int, identifier: bool = False) -> list[str]:
    items = _sequence(value, name, minimum=1, maximum=maximum)
    result = [_string(item, f"{name}[]", identifier=identifier) for item in items]
    if len(set(result)) != len(result):
        _reject(f"{name} contains duplicates")
    return result


def _unique_fingerprints(value: Any, name: str, *, maximum: int = MAX_CERTIFICATES) -> list[str]:
    items = _sequence(value, name, minimum=1, maximum=maximum)
    result = [_fingerprint(item, f"{name}[]") for item in items]
    if len(set(result)) != len(result):
        _reject(f"{name} contains duplicates")
    return result


def _canonical_digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _private_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _validate_policy(raw: Any) -> dict[str, Any]:
    policy = _mapping(raw, "policy", POLICY_KEYS)
    clients = _unique_strings(
        policy["required_clients"],
        "policy.required_clients",
        maximum=MAX_IDENTITIES,
        identifier=True,
    )
    instances = _unique_strings(
        policy["required_instances"],
        "policy.required_instances",
        maximum=MAX_IDENTITIES,
        identifier=True,
    )
    if len(clients) * len(instances) > MAX_OBSERVATIONS:
        _reject("required client/instance matrix exceeds the observation budget")
    return {
        "required_clients": clients,
        "required_instances": instances,
        "min_overlap_seconds": _integer(
            policy["min_overlap_seconds"],
            "policy.min_overlap_seconds",
            minimum=60,
            maximum=2_592_000,
        ),
        "min_remaining_validity_seconds": _integer(
            policy["min_remaining_validity_seconds"],
            "policy.min_remaining_validity_seconds",
            minimum=60,
            maximum=31_536_000,
        ),
        "max_evidence_age_seconds": _integer(
            policy["max_evidence_age_seconds"],
            "policy.max_evidence_age_seconds",
            minimum=1,
            maximum=604_800,
        ),
        "max_future_skew_seconds": _integer(
            policy["max_future_skew_seconds"],
            "policy.max_future_skew_seconds",
            minimum=0,
            maximum=3_600,
        ),
        "min_successes_per_pair": _integer(
            policy["min_successes_per_pair"],
            "policy.min_successes_per_pair",
            minimum=1,
            maximum=1_000_000,
        ),
        "max_failure_rate": _number(
            policy["max_failure_rate"], "policy.max_failure_rate", minimum=0.0, maximum=0.25
        ),
    }


def _validate_certificates(raw: Any) -> dict[str, dict[str, Any]]:
    items = _sequence(raw, "certificates", minimum=4, maximum=MAX_CERTIFICATES)
    result: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(items):
        cert = _mapping(item, f"certificates[{index}]", CERT_KEYS)
        fingerprint = _fingerprint(cert["fingerprint_sha256"], "certificate fingerprint")
        if fingerprint in result:
            _reject("certificate fingerprints must be unique")
        kind = _string(cert["kind"], "certificate.kind")
        if kind not in {"ca", "leaf"}:
            _reject("certificate.kind must be ca or leaf")
        issuer = _fingerprint(cert["issuer_fingerprint_sha256"], "certificate issuer")
        not_before = _timestamp(cert["not_before"], "certificate.not_before")
        not_after = _timestamp(cert["not_after"], "certificate.not_after")
        if not_before >= not_after:
            _reject("certificate validity interval is empty")
        algorithm = _string(cert["public_key_algorithm"], "certificate.public_key_algorithm")
        if algorithm not in {"RSA", "ECDSA", "Ed25519"}:
            _reject("unsupported public-key algorithm")
        bits = _integer(
            cert["public_key_bits"], "certificate.public_key_bits", minimum=0, maximum=16_384
        )
        sans_raw = _sequence(cert["san_identities"], "certificate.san_identities", maximum=64)
        sans = [_string(entry, "certificate SAN") for entry in sans_raw]
        if len(sans) != len(set(sans)):
            _reject("certificate SANs contain duplicates")
        eku_raw = _sequence(
            cert["extended_key_usage"], "certificate.extended_key_usage", maximum=16
        )
        eku = [_string(entry, "certificate EKU", identifier=True) for entry in eku_raw]
        if len(eku) != len(set(eku)):
            _reject("certificate EKUs contain duplicates")
        result[fingerprint] = {
            "fingerprint": fingerprint,
            "kind": kind,
            "issuer": issuer,
            "not_before": not_before,
            "not_after": not_after,
            "algorithm": algorithm,
            "bits": bits,
            "sans": sans,
            "eku": eku,
        }
    return result


def _validate_refs(raw: Any, certificates: Mapping[str, Any]) -> dict[str, str]:
    refs_raw = _mapping(raw, "certificate_refs", REF_KEYS)
    refs = {key: _fingerprint(value, f"certificate_refs.{key}") for key, value in refs_raw.items()}
    if len(set(refs.values())) != 4:
        _reject("certificate references must be distinct")
    if not set(refs.values()) <= set(certificates):
        _reject("certificate reference is absent from inventory")
    return refs


def _validate_phases(raw: Any) -> list[dict[str, Any]]:
    items = _sequence(raw, "phases", minimum=3, maximum=3)
    result: list[dict[str, Any]] = []
    for index, item in enumerate(items):
        phase = _mapping(item, f"phases[{index}]", PHASE_KEYS)
        name = _string(phase["name"], "phase.name", identifier=True)
        if name != PHASE_NAMES[index]:
            _reject("phases are missing or out of order")
        started = _timestamp(phase["started_at"], "phase.started_at")
        completed = _timestamp(phase["completed_at"], "phase.completed_at")
        if started >= completed:
            _reject("phase interval must be positive")
        presentations_raw = _sequence(
            phase["presentations"], "phase.presentations", minimum=1, maximum=MAX_IDENTITIES
        )
        presentations: dict[str, str] = {}
        for entry in presentations_raw:
            value = _mapping(entry, "presentation", PRESENTATION_KEYS)
            instance = _string(value["instance_id"], "presentation.instance_id", identifier=True)
            if instance in presentations:
                _reject("phase has duplicate instance presentations")
            presentations[instance] = _fingerprint(
                value["leaf_fingerprint_sha256"], "presentation.leaf_fingerprint_sha256"
            )
        observations_raw = _sequence(
            phase["observations"], "phase.observations", minimum=1, maximum=MAX_OBSERVATIONS
        )
        observations: list[dict[str, Any]] = []
        seen_pairs: set[tuple[str, str]] = set()
        for entry in observations_raw:
            value = _mapping(entry, "observation", OBSERVATION_KEYS)
            client = _string(value["client_id"], "observation.client_id", identifier=True)
            instance = _string(value["instance_id"], "observation.instance_id", identifier=True)
            pair = (client, instance)
            if pair in seen_pairs:
                _reject("phase has duplicate client/instance observations")
            seen_pairs.add(pair)
            attempts = _integer(
                value["attempts"], "observation.attempts", minimum=1, maximum=1_000_000
            )
            successes = _integer(
                value["successes"], "observation.successes", minimum=0, maximum=1_000_000
            )
            if successes > attempts:
                _reject("observation successes exceed attempts")
            failure_codes_raw = value["failure_codes"]
            if not isinstance(failure_codes_raw, dict) or len(failure_codes_raw) > 32:
                _reject("observation.failure_codes must be a bounded object")
            failure_codes: dict[str, int] = {}
            for code, count in failure_codes_raw.items():
                normalized = _string(code, "failure code", identifier=True)
                failure_codes[normalized] = _integer(
                    count, "failure count", minimum=1, maximum=1_000_000
                )
            if sum(failure_codes.values()) != attempts - successes:
                _reject("failure-code counts do not reconcile with attempts")
            observations.append(
                {
                    "client": client,
                    "instance": instance,
                    "trusted": _unique_fingerprints(
                        value["trusted_ca_fingerprints"], "observation.trusted_ca_fingerprints"
                    ),
                    "leaf": _fingerprint(
                        value["presented_leaf_fingerprint_sha256"], "observation leaf"
                    ),
                    "verified_ca": _fingerprint(
                        value["verified_ca_fingerprint_sha256"], "observation verified CA"
                    ),
                    "attempts": attempts,
                    "successes": successes,
                    "failure_codes": failure_codes,
                }
            )
        result.append(
            {
                "name": name,
                "started": started,
                "completed": completed,
                "trusted": _unique_fingerprints(
                    phase["trusted_ca_fingerprints"], "phase.trusted_ca_fingerprints"
                ),
                "presentations": presentations,
                "observations": observations,
            }
        )
    return result


def _key_is_strong(cert: Mapping[str, Any]) -> bool:
    return bool(
        (cert["algorithm"] == "RSA" and cert["bits"] >= 2048)
        or (cert["algorithm"] == "ECDSA" and cert["bits"] >= 256)
        or (cert["algorithm"] == "Ed25519" and cert["bits"] in {0, 255, 256})
    )


def audit_artifact(artifact: Mapping[str, Any], *, evaluated_at: datetime) -> dict[str, Any]:
    """Validate and evaluate one complete rotation artifact."""

    root = _mapping(dict(artifact), "artifact", TOP_KEYS)
    if root["schema_version"] != 1:
        _reject("unsupported schema_version")
    rotation_id = _string(root["rotation_id"], "rotation_id", identifier=True)
    service_identity = _string(root["service_identity"], "service_identity")
    policy_version = _string(root["policy_version"], "policy_version", identifier=True)
    collected_at = _timestamp(root["collected_at"], "collected_at")
    if evaluated_at.tzinfo is None or evaluated_at.utcoffset() != UTC.utcoffset(evaluated_at):
        _reject("evaluated_at must be timezone-aware UTC")
    policy = _validate_policy(root["policy"])
    certificates = _validate_certificates(root["certificates"])
    refs = _validate_refs(root["certificate_refs"], certificates)
    phases = _validate_phases(root["phases"])
    findings: list[Finding] = []

    age = (evaluated_at - collected_at).total_seconds()
    if age > policy["max_evidence_age_seconds"]:
        findings.append(Finding("EVIDENCE_STALE"))
    if age < -policy["max_future_skew_seconds"]:
        findings.append(Finding("EVIDENCE_FROM_FUTURE"))

    old_ca = certificates[refs["old_ca"]]
    new_ca = certificates[refs["new_ca"]]
    old_leaf = certificates[refs["old_leaf"]]
    new_leaf = certificates[refs["new_leaf"]]
    for label, cert in (("OLD_CA", old_ca), ("NEW_CA", new_ca)):
        if cert["kind"] != "ca" or cert["issuer"] != cert["fingerprint"]:
            findings.append(Finding(f"{label}_NOT_SELF_ISSUED_CA"))
    for label, cert, ca in (
        ("OLD_LEAF", old_leaf, old_ca),
        ("NEW_LEAF", new_leaf, new_ca),
    ):
        if cert["kind"] != "leaf" or cert["issuer"] != ca["fingerprint"]:
            findings.append(Finding(f"{label}_CHAIN_MISMATCH"))
        if service_identity not in cert["sans"]:
            findings.append(Finding(f"{label}_IDENTITY_MISMATCH"))
        if "serverAuth" not in cert["eku"]:
            findings.append(Finding(f"{label}_SERVER_AUTH_MISSING"))
    for label, cert in (
        ("OLD_CA", old_ca),
        ("NEW_CA", new_ca),
        ("OLD_LEAF", old_leaf),
        ("NEW_LEAF", new_leaf),
    ):
        if not _key_is_strong(cert):
            findings.append(Finding(f"{label}_WEAK_KEY"))
        if not cert["not_before"] <= collected_at < cert["not_after"]:
            findings.append(Finding(f"{label}_NOT_VALID_AT_COLLECTION"))
    remaining = min(
        int((new_ca["not_after"] - collected_at).total_seconds()),
        int((new_leaf["not_after"] - collected_at).total_seconds()),
    )
    if remaining < policy["min_remaining_validity_seconds"]:
        findings.append(Finding("NEW_CHAIN_VALIDITY_TOO_SHORT"))

    for before, after in pairwise(phases):
        if before["completed"] > after["started"]:
            findings.append(Finding("PHASES_OVERLAP_OR_REORDERED"))
    overlap_seconds = int((phases[2]["started"] - phases[0]["started"]).total_seconds())
    if overlap_seconds < policy["min_overlap_seconds"]:
        findings.append(Finding("DUAL_TRUST_OVERLAP_TOO_SHORT"))
    if collected_at < phases[-1]["completed"]:
        findings.append(Finding("COLLECTION_PRECEDES_ROTATION_COMPLETION"))

    old_ca_fp, new_ca_fp = refs["old_ca"], refs["new_ca"]
    expected_trust = ({old_ca_fp, new_ca_fp}, {old_ca_fp, new_ca_fp}, {new_ca_fp})
    expected_leaf = (refs["old_leaf"], refs["new_leaf"], refs["new_leaf"])
    expected_pairs = {
        (client, instance)
        for client in policy["required_clients"]
        for instance in policy["required_instances"]
    }
    phase_metrics: list[dict[str, Any]] = []
    for phase, trust, leaf in zip(phases, expected_trust, expected_leaf, strict=True):
        phase_name = phase["name"]
        if set(phase["trusted"]) != trust:
            findings.append(Finding("PHASE_TRUST_SET_MISMATCH", phase_name))
        if set(phase["presentations"]) != set(policy["required_instances"]):
            findings.append(Finding("INSTANCE_COVERAGE_INCOMPLETE", phase_name))
        if any(value != leaf for value in phase["presentations"].values()):
            findings.append(Finding("PRESENTED_LEAF_MISMATCH", phase_name))
        observed_pairs = {(item["client"], item["instance"]) for item in phase["observations"]}
        if observed_pairs != expected_pairs:
            findings.append(Finding("HANDSHAKE_MATRIX_INCOMPLETE", phase_name))
        attempts = sum(item["attempts"] for item in phase["observations"])
        successes = sum(item["successes"] for item in phase["observations"])
        for observation in phase["observations"]:
            if set(observation["trusted"]) != trust:
                findings.append(Finding("CLIENT_TRUST_SET_MISMATCH", phase_name))
            if observation["leaf"] != leaf:
                findings.append(Finding("OBSERVED_LEAF_MISMATCH", phase_name))
            if observation["verified_ca"] != (old_ca_fp if leaf == refs["old_leaf"] else new_ca_fp):
                findings.append(Finding("VERIFIED_CA_MISMATCH", phase_name))
            if observation["successes"] < policy["min_successes_per_pair"]:
                findings.append(Finding("PAIR_SUCCESS_BUDGET_NOT_MET", phase_name))
        failure_rate = 1.0 - successes / attempts
        if failure_rate > policy["max_failure_rate"]:
            findings.append(Finding("PHASE_FAILURE_RATE_EXCEEDED", phase_name))
        phase_metrics.append(
            {
                "name": phase_name,
                "attempts": attempts,
                "successes": successes,
                "failure_rate": round(failure_rate, 12),
                "observed_pairs": len(observed_pairs),
                "required_pairs": len(expected_pairs),
            }
        )

    unique_findings = sorted(
        {(finding.code, finding.phase) for finding in findings},
        key=lambda item: (item[0], item[1] or ""),
    )
    report: dict[str, Any] = {
        "schema_version": 1,
        "decision": "accept" if not unique_findings else "reject",
        "evaluated_at": evaluated_at.isoformat().replace("+00:00", "Z"),
        "rotation_id_sha256": _private_hash(rotation_id),
        "service_identity_sha256": _private_hash(service_identity),
        "policy_version_sha256": _private_hash(policy_version),
        "artifact_sha256": _canonical_digest(root),
        "policy_sha256": _canonical_digest(root["policy"]),
        "metrics": {
            "dual_trust_overlap_seconds": overlap_seconds,
            "new_chain_remaining_validity_seconds": remaining,
            "phases": phase_metrics,
        },
        "findings": [Finding(code=code, phase=phase).as_dict() for code, phase in unique_findings],
    }
    report["evidence_sha256"] = _canonical_digest(report)
    return report


def _parse_at(value: str | None) -> datetime:
    if value is None:
        return datetime.now(UTC)
    return _timestamp(value, "--at")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path, help="normalized mTLS rotation evidence JSON")
    parser.add_argument(
        "--at", help="deterministic UTC evaluation time, for example 2026-09-27T07:00:00Z"
    )
    args = parser.parse_args(argv)
    try:
        artifact = load_artifact(args.artifact)
        report = audit_artifact(artifact, evaluated_at=_parse_at(args.at))
    except ArtifactError as exc:
        print(json.dumps({"decision": "malformed", "error": str(exc)}, sort_keys=True))
        return 3
    print(json.dumps(report, allow_nan=False, separators=(",", ":"), sort_keys=True))
    return 0 if report["decision"] == "accept" else 2


if __name__ == "__main__":
    sys.exit(main())
