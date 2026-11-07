from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from tools.archive_network_loss_release import (
    ARCHIVE_BUNDLE_SCHEMA,
    ARCHIVE_RECEIPT_SCHEMA,
    ReleaseArchiveRejected,
    publish_release_bundle,
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
NOW = datetime(2026, 11, 5, 16, 35, tzinfo=timezone.utc)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _benchmark(
    *, failures: int = 4, elapsed_ms: int = 700
) -> PartialLossBenchmarkEvidence:
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
            elapsed_ms=elapsed_ms,
        ),
        QdiscTrafficDelta(packets=800, bytes=72_000, drops=200, overlimits=0),
        configured_loss_percent=20,
        seed=12_648_430,
        runtime_fingerprint=fingerprint,
    )


def _release_documents(
    *, candidate_failures: int = 5, candidate_elapsed_ms: int = 770
) -> tuple[
    object, object, object, PartialLossBenchmarkEvidence, PartialLossBenchmarkEvidence
]:
    baseline = _benchmark()
    candidate = _benchmark(
        failures=candidate_failures,
        elapsed_ms=candidate_elapsed_ms,
    )
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


class FakeS3:
    def __init__(self) -> None:
        self.put_request: dict[str, Any] | None = None
        self.versioning: dict[str, object] = {"Status": "Enabled"}
        self.lock: dict[str, object] = {
            "ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled"}
        }
        self.public_access: dict[str, object] = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }
        self.corrupt_checksum = False
        self.retention_mode = "COMPLIANCE"

    def get_bucket_versioning(self, **_kwargs: object) -> dict[str, Any]:
        return self.versioning

    def get_object_lock_configuration(self, **_kwargs: object) -> dict[str, Any]:
        return self.lock

    def get_public_access_block(self, **_kwargs: object) -> dict[str, Any]:
        return self.public_access

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
        checksum = self.put_request["ChecksumSHA256"]
        return {
            "Checksum": {
                "ChecksumSHA256": "invalid" if self.corrupt_checksum else checksum
            },
            "ObjectSize": len(self.put_request["Body"]),
        }

    def get_object_retention(self, **_kwargs: object) -> dict[str, Any]:
        assert self.put_request is not None
        return {
            "Retention": {
                "Mode": self.retention_mode,
                "RetainUntilDate": self.put_request["ObjectLockRetainUntilDate"],
            }
        }


def _publish(client_factory: Any, documents: tuple[object, ...]) -> dict[str, object]:
    authorization, status, epoch, baseline, candidate = documents
    return publish_release_bundle(
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
        client_factory=client_factory,
        signature_verifier=lambda *_: True,
        status_signature_verifier=lambda *_: True,
        release_signature_verifier=lambda *_: True,
        clock=lambda: NOW,
    )


def test_publishes_canonical_content_addressed_compliance_version() -> None:
    client = FakeS3()
    receipt = _publish(lambda: client, _release_documents())

    assert client.put_request is not None
    request = client.put_request
    bundle = json.loads(request["Body"])
    assert bundle["schema_version"] == ARCHIVE_BUNDLE_SCHEMA
    assert bundle["gate_receipt"]["status"] == "pass"
    assert request["IfNoneMatch"] == "*"
    assert request["ObjectLockMode"] == "COMPLIANCE"
    assert request["ObjectLockRetainUntilDate"] == NOW + timedelta(days=365)
    assert request["ServerSideEncryption"] == "aws:kms"
    assert request["SSEKMSKeyId"] == KMS_KEY_ARN
    assert request["ExpectedBucketOwner"] == ACCOUNT_ID
    assert request["Key"] == f"netem/releases/{receipt['bundle_sha256']}.json"
    assert receipt["schema_version"] == ARCHIVE_RECEIPT_SCHEMA
    assert receipt["version_id"] == "release-version-1"
    serialized_receipt = json.dumps(receipt)
    assert BUCKET not in serialized_receipt
    assert KMS_KEY_ARN not in serialized_receipt


def test_gate_rejection_happens_before_client_creation() -> None:
    authorization, status, epoch, baseline, _candidate = _release_documents()
    substituted_candidate = _benchmark(failures=6, elapsed_ms=770)
    created = False

    def forbidden_factory() -> FakeS3:
        nonlocal created
        created = True
        raise AssertionError("client created before gate verification")

    with pytest.raises(ReleaseArchiveRejected, match="gate verification"):
        _publish(
            forbidden_factory,
            (authorization, status, epoch, baseline, substituted_candidate),
        )
    assert created is False


def test_over_budget_release_is_not_archived() -> None:
    created = False

    def forbidden_factory() -> FakeS3:
        nonlocal created
        created = True
        return FakeS3()

    with pytest.raises(ReleaseArchiveRejected, match="only an accepted release"):
        _publish(
            forbidden_factory,
            _release_documents(candidate_failures=12, candidate_elapsed_ms=900),
        )
    assert created is False


@pytest.mark.parametrize("control", ["versioning", "lock", "public_access"])
def test_rejects_unsafe_bucket_controls_before_write(control: str) -> None:
    client = FakeS3()
    if control == "versioning":
        client.versioning = {"Status": "Suspended"}
    elif control == "lock":
        client.lock = {"ObjectLockConfiguration": {"ObjectLockEnabled": "Disabled"}}
    else:
        client.public_access["PublicAccessBlockConfiguration"]["BlockPublicPolicy"] = (
            False
        )

    with pytest.raises(ReleaseArchiveRejected):
        _publish(lambda: client, _release_documents())
    assert client.put_request is None


@pytest.mark.parametrize("failure", ["checksum", "retention"])
def test_rejects_stored_version_integrity_or_retention_drift(failure: str) -> None:
    client = FakeS3()
    if failure == "checksum":
        client.corrupt_checksum = True
    else:
        client.retention_mode = "GOVERNANCE"
    with pytest.raises(ReleaseArchiveRejected, match="integrity or retention"):
        _publish(lambda: client, _release_documents())
