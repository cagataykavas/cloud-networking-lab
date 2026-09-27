from __future__ import annotations

import copy
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from tools.mtls_rotation_audit import ArtifactError, audit_artifact, load_artifact

OLD_CA = "1" * 64
NEW_CA = "2" * 64
OLD_LEAF = "3" * 64
NEW_LEAF = "4" * 64
AT = datetime(2026, 9, 27, 7, 0, tzinfo=UTC)


def certificate(
    fingerprint: str,
    kind: str,
    issuer: str,
    *,
    sans: list[str] | None = None,
    eku: list[str] | None = None,
) -> dict[str, object]:
    return {
        "fingerprint_sha256": fingerprint,
        "kind": kind,
        "issuer_fingerprint_sha256": issuer,
        "not_before": "2026-09-01T00:00:00Z",
        "not_after": "2027-09-01T00:00:00Z",
        "public_key_algorithm": "ECDSA",
        "public_key_bits": 256,
        "san_identities": sans or [],
        "extended_key_usage": eku or [],
    }


def observation(
    client: str, instance: str, trust: list[str], leaf: str, ca: str
) -> dict[str, object]:
    return {
        "client_id": client,
        "instance_id": instance,
        "trusted_ca_fingerprints": trust,
        "presented_leaf_fingerprint_sha256": leaf,
        "verified_ca_fingerprint_sha256": ca,
        "attempts": 100,
        "successes": 100,
        "failure_codes": {},
    }


def phase(
    name: str,
    started: str,
    completed: str,
    trust: list[str],
    leaf: str,
    ca: str,
) -> dict[str, object]:
    clients = ["edge-a", "edge-b"]
    instances = ["api-a", "api-b"]
    return {
        "name": name,
        "started_at": started,
        "completed_at": completed,
        "trusted_ca_fingerprints": trust,
        "presentations": [
            {"instance_id": instance, "leaf_fingerprint_sha256": leaf} for instance in instances
        ],
        "observations": [
            observation(client, instance, trust, leaf, ca)
            for client in clients
            for instance in instances
        ],
    }


def valid_artifact() -> dict[str, object]:
    identity = "spiffe://example.internal/ns/prod/sa/api"
    dual_trust = [OLD_CA, NEW_CA]
    return {
        "schema_version": 1,
        "rotation_id": "rot-2026-09",
        "service_identity": identity,
        "policy_version": "mtls-v1",
        "collected_at": "2026-09-27T06:45:00Z",
        "policy": {
            "required_clients": ["edge-a", "edge-b"],
            "required_instances": ["api-a", "api-b"],
            "min_overlap_seconds": 1800,
            "min_remaining_validity_seconds": 604800,
            "max_evidence_age_seconds": 3600,
            "max_future_skew_seconds": 30,
            "min_successes_per_pair": 50,
            "max_failure_rate": 0.001,
        },
        "certificate_refs": {
            "old_ca": OLD_CA,
            "new_ca": NEW_CA,
            "old_leaf": OLD_LEAF,
            "new_leaf": NEW_LEAF,
        },
        "certificates": [
            certificate(OLD_CA, "ca", OLD_CA),
            certificate(NEW_CA, "ca", NEW_CA),
            certificate(OLD_LEAF, "leaf", OLD_CA, sans=[identity], eku=["serverAuth"]),
            certificate(NEW_LEAF, "leaf", NEW_CA, sans=[identity], eku=["serverAuth"]),
        ],
        "phases": [
            phase(
                "dual_trust_old_leaf",
                "2026-09-27T05:00:00Z",
                "2026-09-27T05:10:00Z",
                dual_trust,
                OLD_LEAF,
                OLD_CA,
            ),
            phase(
                "dual_trust_new_leaf",
                "2026-09-27T05:15:00Z",
                "2026-09-27T05:30:00Z",
                dual_trust,
                NEW_LEAF,
                NEW_CA,
            ),
            phase(
                "new_trust_only",
                "2026-09-27T06:00:00Z",
                "2026-09-27T06:15:00Z",
                [NEW_CA],
                NEW_LEAF,
                NEW_CA,
            ),
        ],
    }


def codes(report: dict[str, object]) -> set[str]:
    return {item["code"] for item in report["findings"]}  # type: ignore[index]


def test_accepts_complete_rotation_and_is_deterministic() -> None:
    first = audit_artifact(valid_artifact(), evaluated_at=AT)
    second = audit_artifact(valid_artifact(), evaluated_at=AT)
    assert first == second
    assert first["decision"] == "accept"
    assert first["findings"] == []
    assert first["metrics"]["dual_trust_overlap_seconds"] == 3600  # type: ignore[index]
    assert len(first["evidence_sha256"]) == 64


@pytest.mark.parametrize(
    ("index", "trust", "expected"),
    [
        (0, [OLD_CA], "PHASE_TRUST_SET_MISMATCH"),
        (1, [NEW_CA], "PHASE_TRUST_SET_MISMATCH"),
        (2, [OLD_CA, NEW_CA], "PHASE_TRUST_SET_MISMATCH"),
    ],
)
def test_rejects_incorrect_phase_trust_sets(index: int, trust: list[str], expected: str) -> None:
    artifact = valid_artifact()
    artifact["phases"][index]["trusted_ca_fingerprints"] = trust  # type: ignore[index]
    assert expected in codes(audit_artifact(artifact, evaluated_at=AT))


def test_rejects_client_trust_drift() -> None:
    artifact = valid_artifact()
    artifact["phases"][1]["observations"][0]["trusted_ca_fingerprints"] = [NEW_CA]  # type: ignore[index]
    report = audit_artifact(artifact, evaluated_at=AT)
    assert "CLIENT_TRUST_SET_MISMATCH" in codes(report)
    assert report["decision"] == "reject"


def test_rejects_incomplete_instance_coverage() -> None:
    artifact = valid_artifact()
    artifact["phases"][1]["presentations"].pop()  # type: ignore[index]
    assert "INSTANCE_COVERAGE_INCOMPLETE" in codes(audit_artifact(artifact, evaluated_at=AT))


def test_rejects_incomplete_handshake_matrix() -> None:
    artifact = valid_artifact()
    artifact["phases"][2]["observations"].pop()  # type: ignore[index]
    assert "HANDSHAKE_MATRIX_INCOMPLETE" in codes(audit_artifact(artifact, evaluated_at=AT))


def test_rejects_weak_pair_evidence() -> None:
    artifact = valid_artifact()
    item = artifact["phases"][1]["observations"][0]  # type: ignore[index]
    item["attempts"] = 50
    item["successes"] = 49
    item["failure_codes"] = {"tls_alert": 1}
    report = audit_artifact(artifact, evaluated_at=AT)
    assert {"PAIR_SUCCESS_BUDGET_NOT_MET", "PHASE_FAILURE_RATE_EXCEEDED"} <= codes(report)


def test_rejects_verified_chain_mismatch() -> None:
    artifact = valid_artifact()
    artifact["phases"][1]["observations"][0]["verified_ca_fingerprint_sha256"] = OLD_CA  # type: ignore[index]
    assert "VERIFIED_CA_MISMATCH" in codes(audit_artifact(artifact, evaluated_at=AT))


def test_rejects_short_overlap() -> None:
    artifact = valid_artifact()
    artifact["phases"][2]["started_at"] = "2026-09-27T05:20:00Z"  # type: ignore[index]
    artifact["phases"][2]["completed_at"] = "2026-09-27T05:40:00Z"  # type: ignore[index]
    assert "DUAL_TRUST_OVERLAP_TOO_SHORT" in codes(audit_artifact(artifact, evaluated_at=AT))


def test_rejects_overlapping_phase_intervals() -> None:
    artifact = valid_artifact()
    artifact["phases"][1]["started_at"] = "2026-09-27T05:05:00Z"  # type: ignore[index]
    assert "PHASES_OVERLAP_OR_REORDERED" in codes(audit_artifact(artifact, evaluated_at=AT))


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("issuer_fingerprint_sha256", OLD_CA, "NEW_LEAF_CHAIN_MISMATCH"),
        ("san_identities", ["spiffe://wrong"], "NEW_LEAF_IDENTITY_MISMATCH"),
        ("extended_key_usage", [], "NEW_LEAF_SERVER_AUTH_MISSING"),
        ("public_key_bits", 128, "NEW_LEAF_WEAK_KEY"),
    ],
)
def test_rejects_invalid_new_leaf(field: str, value: object, expected: str) -> None:
    artifact = valid_artifact()
    artifact["certificates"][3][field] = value  # type: ignore[index]
    assert expected in codes(audit_artifact(artifact, evaluated_at=AT))


def test_rejects_short_new_chain_validity() -> None:
    artifact = valid_artifact()
    artifact["certificates"][3]["not_after"] = "2026-09-28T00:00:00Z"  # type: ignore[index]
    assert "NEW_CHAIN_VALIDITY_TOO_SHORT" in codes(audit_artifact(artifact, evaluated_at=AT))


@pytest.mark.parametrize(
    ("collected_at", "expected"),
    [
        ("2026-09-27T05:00:00Z", "EVIDENCE_STALE"),
        ("2026-09-27T07:01:00Z", "EVIDENCE_FROM_FUTURE"),
    ],
)
def test_rejects_bad_evidence_time(collected_at: str, expected: str) -> None:
    artifact = valid_artifact()
    artifact["collected_at"] = collected_at
    assert expected in codes(audit_artifact(artifact, evaluated_at=AT))


def test_report_does_not_disclose_identity_or_rotation_id() -> None:
    artifact = valid_artifact()
    report_text = json.dumps(audit_artifact(artifact, evaluated_at=AT))
    assert artifact["service_identity"] not in report_text
    assert artifact["rotation_id"] not in report_text


@pytest.mark.parametrize("value", [float("nan"), float("inf"), True, -1])
def test_rejects_invalid_failure_rate(value: object) -> None:
    artifact = valid_artifact()
    artifact["policy"]["max_failure_rate"] = value  # type: ignore[index]
    with pytest.raises(ArtifactError):
        audit_artifact(artifact, evaluated_at=AT)


def test_rejects_unreconciled_failure_codes() -> None:
    artifact = valid_artifact()
    item = artifact["phases"][0]["observations"][0]  # type: ignore[index]
    item["successes"] = 99
    with pytest.raises(ArtifactError, match="reconcile"):
        audit_artifact(artifact, evaluated_at=AT)


def test_rejects_duplicate_observation_pair() -> None:
    artifact = valid_artifact()
    observations = artifact["phases"][0]["observations"]  # type: ignore[index]
    observations.append(copy.deepcopy(observations[0]))
    with pytest.raises(ArtifactError, match="duplicate client/instance"):
        audit_artifact(artifact, evaluated_at=AT)


def test_load_rejects_duplicate_json_members(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text('{"schema_version":1,"schema_version":1}')
    with pytest.raises(ArtifactError, match="duplicate"):
        load_artifact(path)


def test_load_rejects_non_finite_json(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text('{"value":NaN}')
    with pytest.raises(ArtifactError, match="non-finite"):
        load_artifact(path)


def test_load_rejects_oversized_artifact(tmp_path: Path) -> None:
    path = tmp_path / "large.json"
    path.write_bytes(b" " * 131_073)
    with pytest.raises(ArtifactError, match="size"):
        load_artifact(path)


def test_cli_exit_codes(tmp_path: Path) -> None:
    accepted = tmp_path / "accepted.json"
    accepted.write_text(json.dumps(valid_artifact()))
    command = [
        sys.executable,
        "tools/mtls_rotation_audit.py",
        str(accepted),
        "--at",
        "2026-09-27T07:00:00Z",
    ]
    success = subprocess.run(command, check=False, capture_output=True, text=True)
    assert success.returncode == 0
    assert json.loads(success.stdout)["decision"] == "accept"

    rejected_payload = valid_artifact()
    rejected_payload["phases"][2]["trusted_ca_fingerprints"] = [OLD_CA, NEW_CA]  # type: ignore[index]
    rejected = tmp_path / "rejected.json"
    rejected.write_text(json.dumps(rejected_payload))
    policy_failure = subprocess.run(
        [
            sys.executable,
            "tools/mtls_rotation_audit.py",
            str(rejected),
            "--at",
            "2026-09-27T07:00:00Z",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert policy_failure.returncode == 2
    assert json.loads(policy_failure.stdout)["decision"] == "reject"

    malformed = tmp_path / "malformed.json"
    malformed.write_text("{}")
    input_failure = subprocess.run(
        [
            sys.executable,
            "tools/mtls_rotation_audit.py",
            str(malformed),
            "--at",
            "2026-09-27T07:00:00Z",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert input_failure.returncode == 3
    assert json.loads(input_failure.stdout)["decision"] == "malformed"
