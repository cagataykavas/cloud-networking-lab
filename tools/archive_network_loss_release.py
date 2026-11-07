#!/usr/bin/env python3
"""Publish an accepted netem release decision to an immutable S3 version."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol

from tools.authorize_network_loss_baseline import (
    gate_authorized_comparison,
    load_authorization,
    verify_ed25519_signature,
)
from tools.compare_network_loss_evidence import load_evidence, write_receipt
from tools.network_loss_release_epoch import load_release_epoch
from tools.network_loss_evidence import PartialLossBenchmarkEvidence
from tools.network_loss_selector_key_status import load_selector_key_status


ARCHIVE_BUNDLE_SCHEMA = "netem-release-archive/v1"
ARCHIVE_RECEIPT_SCHEMA = "netem-release-archive-receipt/v1"
MAX_RETENTION_DAYS = 3_650

_ACCOUNT_ID = re.compile(r"[0-9]{12}")
_BUCKET = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]")
_KMS_KEY_ARN = re.compile(
    r"arn:(?:aws|aws-us-gov|aws-cn):kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-fA-F-]{36}"
)
_PREFIX = re.compile(r"[A-Za-z0-9][A-Za-z0-9!_.*'()/=-]{0,255}")
_REGION = re.compile(r"[a-z]{2}(?:-gov)?-[a-z]+-[0-9]")

SignatureVerifier = Callable[[bytes, bytes, bytes], bool]


class S3ArchiveClient(Protocol):
    """The small S3 surface required by the archive boundary."""

    def get_bucket_versioning(self, **kwargs: object) -> dict[str, Any]: ...

    def get_object_lock_configuration(self, **kwargs: object) -> dict[str, Any]: ...

    def get_public_access_block(self, **kwargs: object) -> dict[str, Any]: ...

    def put_object(self, **kwargs: object) -> dict[str, Any]: ...

    def get_object_attributes(self, **kwargs: object) -> dict[str, Any]: ...

    def get_object_retention(self, **kwargs: object) -> dict[str, Any]: ...


ClientFactory = Callable[[], S3ArchiveClient]
Clock = Callable[[], datetime]


class ReleaseArchiveRejected(ValueError):
    """The release or immutable storage boundary failed closed."""


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _validate_destination(
    *,
    bucket: str,
    expected_bucket_owner: str,
    kms_key_arn: str,
    prefix: str,
    retention_days: int,
) -> None:
    if _BUCKET.fullmatch(bucket) is None or ".." in bucket:
        raise ReleaseArchiveRejected("archive bucket name is invalid")
    if _ACCOUNT_ID.fullmatch(expected_bucket_owner) is None:
        raise ReleaseArchiveRejected(
            "expected bucket owner must be a 12-digit account ID"
        )
    if (
        _KMS_KEY_ARN.fullmatch(kms_key_arn) is None
        or f":{expected_bucket_owner}:" not in kms_key_arn
    ):
        raise ReleaseArchiveRejected(
            "KMS key must be a full key ARN in the bucket account"
        )
    if _PREFIX.fullmatch(prefix) is None or prefix.endswith("/"):
        raise ReleaseArchiveRejected("archive prefix is invalid")
    if (
        isinstance(retention_days, bool)
        or not isinstance(retention_days, int)
        or not 1 <= retention_days <= MAX_RETENTION_DAYS
    ):
        raise ReleaseArchiveRejected("retention_days must be an integer in [1, 3650]")


def _require_bucket_controls(
    client: S3ArchiveClient,
    *,
    bucket: str,
    expected_bucket_owner: str,
) -> None:
    request = {"Bucket": bucket, "ExpectedBucketOwner": expected_bucket_owner}
    try:
        versioning = client.get_bucket_versioning(**request)
        object_lock = client.get_object_lock_configuration(**request)
        public_access = client.get_public_access_block(**request)
    except Exception as exc:
        raise ReleaseArchiveRejected(
            "cannot verify immutable archive bucket controls"
        ) from exc
    if versioning.get("Status") != "Enabled":
        raise ReleaseArchiveRejected("archive bucket versioning is not enabled")
    if object_lock.get("ObjectLockConfiguration", {}).get("ObjectLockEnabled") != (
        "Enabled"
    ):
        raise ReleaseArchiveRejected("archive bucket Object Lock is not enabled")
    block = public_access.get("PublicAccessBlockConfiguration")
    required = {
        "BlockPublicAcls",
        "IgnorePublicAcls",
        "BlockPublicPolicy",
        "RestrictPublicBuckets",
    }
    if not isinstance(block, dict) or any(
        block.get(field) is not True for field in required
    ):
        raise ReleaseArchiveRejected(
            "archive bucket public access is not fully blocked"
        )


def publish_release_bundle(
    authorization: object,
    selector_key_status: object,
    release_epoch: object,
    baseline: PartialLossBenchmarkEvidence,
    candidate: PartialLossBenchmarkEvidence,
    *,
    expected_public_key_sha256: str,
    expected_selector_key_id: str,
    expected_status_authority_public_key_sha256: str,
    expected_status_authority_key_id: str,
    expected_release_authority_public_key_sha256: str,
    expected_release_authority_key_id: str,
    repository_id: str,
    workflow_sha: str,
    max_failure_rate_increase_basis_points: int,
    max_elapsed_increase_basis_points: int,
    bucket: str,
    expected_bucket_owner: str,
    kms_key_arn: str,
    prefix: str,
    retention_days: int,
    client_factory: ClientFactory,
    signature_verifier: SignatureVerifier = verify_ed25519_signature,
    status_signature_verifier: SignatureVerifier = verify_ed25519_signature,
    release_signature_verifier: SignatureVerifier = verify_ed25519_signature,
    clock: Clock = lambda: datetime.now(timezone.utc),
) -> dict[str, object]:
    """Verify the complete gate, then publish one content-addressed locked version."""
    _validate_destination(
        bucket=bucket,
        expected_bucket_owner=expected_bucket_owner,
        kms_key_arn=kms_key_arn,
        prefix=prefix,
        retention_days=retention_days,
    )
    try:
        gate_receipt, comparison = gate_authorized_comparison(
            authorization,
            selector_key_status,
            release_epoch,
            baseline,
            candidate,
            expected_public_key_sha256=expected_public_key_sha256,
            expected_selector_key_id=expected_selector_key_id,
            expected_status_authority_public_key_sha256=(
                expected_status_authority_public_key_sha256
            ),
            expected_status_authority_key_id=expected_status_authority_key_id,
            expected_release_authority_public_key_sha256=(
                expected_release_authority_public_key_sha256
            ),
            expected_release_authority_key_id=expected_release_authority_key_id,
            repository_id=repository_id,
            workflow_sha=workflow_sha,
            max_failure_rate_increase_basis_points=(
                max_failure_rate_increase_basis_points
            ),
            max_elapsed_increase_basis_points=(max_elapsed_increase_basis_points),
            signature_verifier=signature_verifier,
            status_signature_verifier=status_signature_verifier,
            release_signature_verifier=release_signature_verifier,
        )
    except (TypeError, ValueError, RuntimeError) as exc:
        raise ReleaseArchiveRejected("release gate verification failed") from exc
    if comparison.accepted is not True:
        raise ReleaseArchiveRejected("only an accepted release may be archived")

    bundle = {
        "authorization": authorization,
        "baseline": baseline.as_dict(),
        "candidate": candidate.as_dict(),
        "gate_receipt": gate_receipt,
        "release_epoch": release_epoch,
        "schema_version": ARCHIVE_BUNDLE_SCHEMA,
        "selector_key_status": selector_key_status,
    }
    body = _canonical(bundle)
    digest_bytes = hashlib.sha256(body).digest()
    digest = digest_bytes.hex()
    checksum = base64.b64encode(digest_bytes).decode("ascii")
    object_key = f"{prefix}/{digest}.json"
    archived_at = clock()
    if archived_at.tzinfo is None or archived_at.utcoffset() is None:
        raise ReleaseArchiveRejected("archive clock must return an aware datetime")
    archived_at = archived_at.astimezone(timezone.utc)
    retain_until = archived_at + timedelta(days=retention_days)

    try:
        client = client_factory()
    except Exception as exc:
        raise ReleaseArchiveRejected("S3 archive client is unavailable") from exc
    _require_bucket_controls(
        client,
        bucket=bucket,
        expected_bucket_owner=expected_bucket_owner,
    )
    try:
        response = client.put_object(
            Bucket=bucket,
            Key=object_key,
            Body=body,
            ContentType="application/json",
            ChecksumAlgorithm="SHA256",
            ChecksumSHA256=checksum,
            ExpectedBucketOwner=expected_bucket_owner,
            IfNoneMatch="*",
            Metadata={"schema": ARCHIVE_BUNDLE_SCHEMA, "sha256": digest},
            ObjectLockMode="COMPLIANCE",
            ObjectLockRetainUntilDate=retain_until,
            ServerSideEncryption="aws:kms",
            SSEKMSKeyId=kms_key_arn,
            BucketKeyEnabled=True,
        )
    except Exception as exc:
        raise ReleaseArchiveRejected("immutable archive write failed") from exc
    version_id = response.get("VersionId")
    if (
        not isinstance(version_id, str)
        or not version_id
        or response.get("ChecksumSHA256") != checksum
        or response.get("ServerSideEncryption") != "aws:kms"
        or response.get("SSEKMSKeyId") != kms_key_arn
    ):
        raise ReleaseArchiveRejected(
            "archive write response is incomplete or mismatched"
        )

    version_request = {
        "Bucket": bucket,
        "Key": object_key,
        "VersionId": version_id,
        "ExpectedBucketOwner": expected_bucket_owner,
    }
    try:
        attributes = client.get_object_attributes(
            **version_request,
            ObjectAttributes=["Checksum", "ObjectSize"],
        )
        retention = client.get_object_retention(**version_request)
    except Exception as exc:
        raise ReleaseArchiveRejected(
            "cannot verify the archived object version"
        ) from exc
    stored_until = retention.get("Retention", {}).get("RetainUntilDate")
    if (
        attributes.get("ObjectSize") != len(body)
        or attributes.get("Checksum", {}).get("ChecksumSHA256") != checksum
        or retention.get("Retention", {}).get("Mode") != "COMPLIANCE"
        or not isinstance(stored_until, datetime)
        or stored_until.tzinfo is None
        or stored_until.astimezone(timezone.utc) < retain_until
    ):
        raise ReleaseArchiveRejected(
            "archived object integrity or retention is mismatched"
        )

    receipt: dict[str, object] = {
        "archived_at": archived_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "bucket_sha256": _sha256(bucket),
        "bundle_sha256": digest,
        "kms_key_arn_sha256": _sha256(kms_key_arn),
        "object_key": object_key,
        "retain_until": stored_until.astimezone(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "schema_version": ARCHIVE_RECEIPT_SCHEMA,
        "version_id": version_id,
    }
    receipt["evidence_sha256"] = hashlib.sha256(_canonical(receipt)).hexdigest()
    return receipt


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Archive an accepted netem release in an S3 Object Lock bucket."
    )
    parser.add_argument("authorization", type=Path)
    parser.add_argument("selector_key_status", type=Path)
    parser.add_argument("release_epoch", type=Path)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--selector-public-key-sha256", required=True)
    parser.add_argument("--selector-key-id", required=True)
    parser.add_argument("--status-authority-public-key-sha256", required=True)
    parser.add_argument("--status-authority-key-id", required=True)
    parser.add_argument("--release-authority-public-key-sha256", required=True)
    parser.add_argument("--release-authority-key-id", required=True)
    parser.add_argument("--repository-id", required=True)
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--expected-bucket-owner", required=True)
    parser.add_argument("--kms-key-arn", required=True)
    parser.add_argument("--prefix", default="netem/releases")
    parser.add_argument("--retention-days", type=int, default=365)
    parser.add_argument("--aws-region", required=True)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--timeout-seconds", type=int, default=10)
    parser.add_argument(
        "--max-failure-rate-increase-basis-points", type=int, default=250
    )
    parser.add_argument("--max-elapsed-increase-basis-points", type=int, default=2_000)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if _REGION.fullmatch(args.aws_region) is None:
            raise ReleaseArchiveRejected("AWS region is invalid")
        inputs = {
            args.authorization.resolve(),
            args.selector_key_status.resolve(),
            args.release_epoch.resolve(),
            args.baseline.resolve(),
            args.candidate.resolve(),
        }
        if len(inputs) != 5 or args.output.resolve() in inputs:
            raise ReleaseArchiveRejected("archive inputs and output must be distinct")

        def client_factory() -> S3ArchiveClient:
            try:
                import boto3
            except ImportError as exc:
                raise RuntimeError("boto3 is not installed") from exc
            return boto3.client("s3", region_name=args.aws_region)

        def verifier(public_key: bytes, signature: bytes, message: bytes) -> bool:
            return verify_ed25519_signature(
                public_key,
                signature,
                message,
                executable=args.openssl,
                timeout_seconds=args.timeout_seconds,
            )

        receipt = publish_release_bundle(
            load_authorization(args.authorization),
            load_selector_key_status(args.selector_key_status),
            load_release_epoch(args.release_epoch),
            load_evidence(args.baseline),
            load_evidence(args.candidate),
            expected_public_key_sha256=args.selector_public_key_sha256,
            expected_selector_key_id=args.selector_key_id,
            expected_status_authority_public_key_sha256=(
                args.status_authority_public_key_sha256
            ),
            expected_status_authority_key_id=args.status_authority_key_id,
            expected_release_authority_public_key_sha256=(
                args.release_authority_public_key_sha256
            ),
            expected_release_authority_key_id=args.release_authority_key_id,
            repository_id=args.repository_id,
            workflow_sha=args.workflow_sha,
            max_failure_rate_increase_basis_points=(
                args.max_failure_rate_increase_basis_points
            ),
            max_elapsed_increase_basis_points=(args.max_elapsed_increase_basis_points),
            bucket=args.bucket,
            expected_bucket_owner=args.expected_bucket_owner,
            kms_key_arn=args.kms_key_arn,
            prefix=args.prefix,
            retention_days=args.retention_days,
            client_factory=client_factory,
            signature_verifier=verifier,
            status_signature_verifier=verifier,
            release_signature_verifier=verifier,
        )
        write_receipt(receipt, args.output)
        return 0
    except (OSError, TypeError, ValueError, RuntimeError) as exc:
        print(f"release archive rejected: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
