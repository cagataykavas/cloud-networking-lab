from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from tools.archive_network_loss_release import (
    ARCHIVE_BUNDLE_SCHEMA,
    publish_release_bundle,
)
from tools.audit_network_loss_release_archive import (
    ARCHIVE_AUDIT_SCHEMA,
    MAX_ARCHIVE_BUNDLE_BYTES,
    ReleaseArchiveAuditRejected,
    audit_release_archive,
    load_archive_receipt,
)
from tools.authorize_network_loss_baseline import create_baseline_authorization
from tools.docker_netem_impairment import (
    RUNTIME_FINGERPRINT_SCHEMA,
    NetemRuntimeFingerprint,
    QdiscTrafficDelta,
)
from tools.network_loss_evidence import (
    PartialLossBenchmarkEvidence,
    ProbeOutcomeSummary,
    verify_partial_loss_benchmark,
)
from tools.network_loss_release_epoch import create_release_epoch
from tools.network_loss_selector_key_status import create_selector_key_status

ACCOUNT_ID = "123456789012"
BUCKET = "private-netem-release-archive"
KMS_KEY_ARN = (
    "arn:aws:kms:eu-central-1:123456789012:key/12345678-1234-1234-1234-123456789abc"
)
PUBLIC_KEY = b"0" * 44
STATUS_KEY = b"1" * 44
RELEASE_KEY = b"2" * 44
PUBLIC_KEY_SHA256 = hashlib.sha256(PUBLIC_KEY).hexdigest()
STATUS_KEY_SHA256 = hashlib.sha256(STATUS_KEY).hexdigest()
RELEASE_KEY_SHA256 = hashlib.sha256(RELEASE_KEY).hexdigest()
SELECTOR_KEY_ID = "netem-selector-2026-11"
STATUS_KEY_ID = "netem-status-2026-11"
RELEASE_KEY_ID = "netem-release-2026-11"
REPOSITORY_ID = "1330973695"
WORKFLOW_SHA = "a" * 40
ISSUED_AT = "2026-11-05T16:00:00Z"
EXPIRES_AT = "2026-11-05T17:00:00Z"
RELEASED_AT = "2026-11-05T16:30:00Z"
ARCHIVED_AT = datetime(2026, 11, 5, 16, 35, tzinfo=UTC)
AUDITED_AT = ARCHIVED_AT + timedelta(hours=1)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _benchmark(*, failures: int = 4) -> PartialLossBenchmarkEvidence:
    fingerprint_payload = _canonical(
        {
            "kernel_release_sha256": "a" * 64,
            "schema_version": RUNTIME_FINGERPRINT_SCHEMA,
            "tc_version_sha256": "b" * 64,
        }
    )
    fingerprint = NetemRuntimeFingerprint(
        kernel_release_sha256="a" * 64,
        tc_version_sha256="b" * 64,
        environment_sha256=hashlib.sha256(fingerprint_payload).hexdigest(),
    )
    return verify_partial_loss_benchmark(
        ProbeOutcomeSummary(
            attempts=128,
            successes=128 - failures,
            failures=failures,
            elapsed_ms=700,
        ),
        QdiscTrafficDelta(packets=800, bytes=72_000, drops=200, overlimits=0),
        configured_loss_percent=20,
        seed=12_648_430,
        runtime_fingerprint=fingerprint,
    )


def _documents() -> tuple[object, ...]:
    baseline = _benchmark()
    candidate = _benchmark(failures=5)
    authorization = create_baseline_authorization(
        baseline,
        max_failure_rate_increase_basis_points=250,
        max_elapsed_increase_basis_points=2_000,
        repository_id=REPOSITORY_ID,
        workflow_sha=WORKFLOW_SHA,
        selector_key_id=SELECTOR_KEY_ID,
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
        public_key_der=PUBLIC_KEY,
        signer=lambda message: b"s" * 64 if message else b"",
    )
    status = create_selector_key_status(
        selector_key_id=SELECTOR_KEY_ID,
        selector_public_key_sha256=PUBLIC_KEY_SHA256,
        state="active",
        status_authority_key_id=STATUS_KEY_ID,
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
        authority_public_key_der=STATUS_KEY,
        signer=lambda message: b"t" * 64 if message else b"",
    )
    epoch = create_release_epoch(
        authorization_sha256=hashlib.sha256(_canonical(authorization)).hexdigest(),
        selector_key_status_sha256=hashlib.sha256(_canonical(status)).hexdigest(),
        baseline_benchmark_sha256=baseline.digest(),
        candidate_benchmark_sha256=candidate.digest(),
        repository_id=REPOSITORY_ID,
        workflow_sha=WORKFLOW_SHA,
        release_authority_key_id=RELEASE_KEY_ID,
        released_at=RELEASED_AT,
        public_key_der=RELEASE_KEY,
        signer=lambda message: b"u" * 64 if message else b"",
    )
    return authorization, status, epoch, baseline, candidate


class ArchiveS3:
    def __init__(self) -> None:
        self.put_request: dict[str, Any] | None = None

    def get_bucket_versioning(self, **_kwargs: object) -> dict[str, Any]:
        return {"Status": "Enabled"}

    def get_object_lock_configuration(self, **_kwargs: object) -> dict[str, Any]:
        return {"ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled"}}

    def get_public_access_block(self, **_kwargs: object) -> dict[str, Any]:
        return {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }

    def put_object(self, **kwargs: object) -> dict[str, Any]:
        self.put_request = kwargs
        return {
            "ChecksumSHA256": kwargs["ChecksumSHA256"],
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": kwargs["SSEKMSKeyId"],
            "VersionId": "release-version-1",
        }

    def get_object_attributes(self, **_kwargs: object) -> dict[str, Any]:
        assert self.put_request is not None
        return {
            "Checksum": {"ChecksumSHA256": self.put_request["ChecksumSHA256"]},
            "ObjectSize": len(self.put_request["Body"]),
        }

    def get_object_retention(self, **_kwargs: object) -> dict[str, Any]:
        assert self.put_request is not None
        return {
            "Retention": {
                "Mode": "COMPLIANCE",
                "RetainUntilDate": self.put_request["ObjectLockRetainUntilDate"],
            }
        }


class Body:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.closed = False

    def read(self, limit: int) -> bytes:
        return self.payload[:limit]

    def close(self) -> None:
        self.closed = True


class AuditS3:
    def __init__(self, body: bytes, receipt: dict[str, object]) -> None:
        self.body = body
        self.receipt = receipt
        self.get_request: dict[str, object] | None = None
        self.retention_mode = "COMPLIANCE"
        self.retained_until = datetime.strptime(
            str(receipt["retain_until"]), "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=UTC)
        self.override: dict[str, object] = {}

    def get_object(self, **kwargs: object) -> dict[str, Any]:
        self.get_request = kwargs
        digest = hashlib.sha256(self.body).digest()
        response: dict[str, object] = {
            "Body": Body(self.body),
            "BucketKeyEnabled": True,
            "ChecksumSHA256": base64.b64encode(digest).decode("ascii"),
            "ContentLength": len(self.body),
            "ContentType": "application/json",
            "Metadata": {
                "schema": ARCHIVE_BUNDLE_SCHEMA,
                "sha256": digest.hex(),
            },
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": KMS_KEY_ARN,
            "VersionId": self.receipt["version_id"],
        }
        response.update(self.override)
        return response

    def get_object_retention(self, **_kwargs: object) -> dict[str, Any]:
        return {
            "Retention": {
                "Mode": self.retention_mode,
                "RetainUntilDate": self.retained_until,
            }
        }


def _archive() -> tuple[dict[str, object], bytes]:
    writer = ArchiveS3()
    authorization, status, epoch, baseline, candidate = _documents()
    receipt = publish_release_bundle(
        authorization,
        status,
        epoch,
        baseline,
        candidate,
        expected_public_key_sha256=PUBLIC_KEY_SHA256,
        expected_selector_key_id=SELECTOR_KEY_ID,
        expected_status_authority_public_key_sha256=STATUS_KEY_SHA256,
        expected_status_authority_key_id=STATUS_KEY_ID,
        expected_release_authority_public_key_sha256=RELEASE_KEY_SHA256,
        expected_release_authority_key_id=RELEASE_KEY_ID,
        repository_id=REPOSITORY_ID,
        workflow_sha=WORKFLOW_SHA,
        max_failure_rate_increase_basis_points=250,
        max_elapsed_increase_basis_points=2_000,
        bucket=BUCKET,
        expected_bucket_owner=ACCOUNT_ID,
        kms_key_arn=KMS_KEY_ARN,
        prefix="netem/releases",
        retention_days=365,
        client_factory=lambda: writer,
        signature_verifier=lambda *_: True,
        status_signature_verifier=lambda *_: True,
        release_signature_verifier=lambda *_: True,
        clock=lambda: ARCHIVED_AT,
    )
    assert writer.put_request is not None
    return receipt, writer.put_request["Body"]


def _audit(
    receipt: dict[str, object],
    client: AuditS3,
    *,
    clock: datetime = AUDITED_AT,
) -> dict[str, object]:
    return audit_release_archive(
        receipt,
        expected_public_key_sha256=PUBLIC_KEY_SHA256,
        expected_selector_key_id=SELECTOR_KEY_ID,
        expected_status_authority_public_key_sha256=STATUS_KEY_SHA256,
        expected_status_authority_key_id=STATUS_KEY_ID,
        expected_release_authority_public_key_sha256=RELEASE_KEY_SHA256,
        expected_release_authority_key_id=RELEASE_KEY_ID,
        repository_id=REPOSITORY_ID,
        workflow_sha=WORKFLOW_SHA,
        max_failure_rate_increase_basis_points=250,
        max_elapsed_increase_basis_points=2_000,
        bucket=BUCKET,
        expected_bucket_owner=ACCOUNT_ID,
        kms_key_arn=KMS_KEY_ARN,
        prefix="netem/releases",
        client_factory=lambda: client,
        signature_verifier=lambda *_: True,
        status_signature_verifier=lambda *_: True,
        release_signature_verifier=lambda *_: True,
        clock=lambda: clock,
    )


def _recommit(receipt: dict[str, object], body: bytes) -> dict[str, object]:
    digest = hashlib.sha256(body).hexdigest()
    changed = dict(receipt)
    changed["bundle_sha256"] = digest
    changed["object_key"] = f"netem/releases/{digest}.json"
    changed.pop("evidence_sha256")
    changed["evidence_sha256"] = hashlib.sha256(_canonical(changed)).hexdigest()
    return changed


def test_recovers_exact_version_replays_gate_and_emits_private_audit() -> None:
    receipt, body = _archive()
    client = AuditS3(body, receipt)
    audit = _audit(receipt, client)

    assert audit["schema_version"] == ARCHIVE_AUDIT_SCHEMA
    assert audit["status"] == "pass"
    assert audit["release_gate_replayed"] is True
    assert audit["storage_checksum_verified"] is True
    assert client.get_request == {
        "Bucket": BUCKET,
        "Key": receipt["object_key"],
        "VersionId": receipt["version_id"],
        "ExpectedBucketOwner": ACCOUNT_ID,
        "ChecksumMode": "ENABLED",
    }
    serialized = json.dumps(audit)
    assert BUCKET not in serialized
    assert KMS_KEY_ARN not in serialized
    assert receipt["version_id"] not in serialized
    assert receipt["object_key"] not in serialized


def test_rejects_tampered_receipt_before_client_creation() -> None:
    receipt, _body = _archive()
    receipt["retain_until"] = "2030-01-01T00:00:00Z"
    created = False

    def forbidden() -> AuditS3:
        nonlocal created
        created = True
        raise AssertionError("client created before receipt verification")

    with pytest.raises(ReleaseArchiveAuditRejected, match="receipt digest"):
        audit_release_archive(
            receipt,
            expected_public_key_sha256=PUBLIC_KEY_SHA256,
            expected_selector_key_id=SELECTOR_KEY_ID,
            expected_status_authority_public_key_sha256=STATUS_KEY_SHA256,
            expected_status_authority_key_id=STATUS_KEY_ID,
            expected_release_authority_public_key_sha256=RELEASE_KEY_SHA256,
            expected_release_authority_key_id=RELEASE_KEY_ID,
            repository_id=REPOSITORY_ID,
            workflow_sha=WORKFLOW_SHA,
            max_failure_rate_increase_basis_points=250,
            max_elapsed_increase_basis_points=2_000,
            bucket=BUCKET,
            expected_bucket_owner=ACCOUNT_ID,
            kms_key_arn=KMS_KEY_ARN,
            prefix="netem/releases",
            client_factory=forbidden,
            clock=lambda: AUDITED_AT,
        )
    assert created is False


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("VersionId", "substituted-version"),
        ("ContentType", "application/octet-stream"),
        ("ChecksumSHA256", "invalid"),
        ("SSEKMSKeyId", "arn:aws:kms:eu-central-1:123456789012:key/wrong"),
        ("BucketKeyEnabled", False),
        ("ContentLength", MAX_ARCHIVE_BUNDLE_BYTES + 1),
    ],
)
def test_rejects_object_control_drift(field: str, value: object) -> None:
    receipt, body = _archive()
    client = AuditS3(body, receipt)
    client.override[field] = value
    with pytest.raises(ReleaseArchiveAuditRejected, match="object controls"):
        _audit(receipt, client)


def test_rejects_recommitted_bundle_with_substituted_gate_receipt() -> None:
    receipt, body = _archive()
    bundle = json.loads(body)
    bundle["gate_receipt"]["status"] = "substituted"
    changed_body = _canonical(bundle)
    changed_receipt = _recommit(receipt, changed_body)
    client = AuditS3(changed_body, changed_receipt)

    with pytest.raises(ReleaseArchiveAuditRejected, match="decision is mismatched"):
        _audit(changed_receipt, client)


@pytest.mark.parametrize("mode", ["GOVERNANCE", ""])
def test_rejects_non_compliance_retention(mode: str) -> None:
    receipt, body = _archive()
    client = AuditS3(body, receipt)
    client.retention_mode = mode
    with pytest.raises(ReleaseArchiveAuditRejected, match="retention controls"):
        _audit(receipt, client)


def test_rejects_shortened_or_expired_retention() -> None:
    receipt, body = _archive()
    shortened = AuditS3(body, receipt)
    shortened.retained_until -= timedelta(seconds=1)
    with pytest.raises(ReleaseArchiveAuditRejected, match="shortened or expired"):
        _audit(receipt, shortened)

    expired = AuditS3(body, receipt)
    with pytest.raises(ReleaseArchiveAuditRejected, match="retention has expired"):
        _audit(receipt, expired, clock=expired.retained_until)


def test_loader_rejects_duplicate_keys_and_symlinks(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema_version":"a","schema_version":"b"}')
    with pytest.raises(ReleaseArchiveAuditRejected, match="duplicate"):
        load_archive_receipt(duplicate)

    target = tmp_path / "receipt.json"
    target.write_text("{}")
    symlink = tmp_path / "receipt-link.json"
    symlink.symlink_to(target)
    with pytest.raises(ReleaseArchiveAuditRejected, match="cannot be opened"):
        load_archive_receipt(symlink)
