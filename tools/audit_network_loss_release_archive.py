#!/usr/bin/env python3
"""Independently recover and audit one immutable netem release archive."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from tools.archive_network_loss_release import (
    ARCHIVE_BUNDLE_SCHEMA,
    ARCHIVE_RECEIPT_SCHEMA,
)
from tools.authorize_network_loss_baseline import (
    gate_authorized_comparison,
    verify_ed25519_signature,
)
from tools.compare_network_loss_evidence import write_receipt
from tools.network_loss_evidence import PartialLossBenchmarkEvidence

ARCHIVE_AUDIT_SCHEMA = "netem-release-archive-audit/v1"
MAX_ARCHIVE_RECEIPT_BYTES = 64 * 1024
MAX_ARCHIVE_BUNDLE_BYTES = 2 * 1024 * 1024

_ACCOUNT_ID = re.compile(r"[0-9]{12}")
_BUCKET = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]")
_HEX_SHA256 = re.compile(r"[0-9a-f]{64}")
_KMS_KEY_ARN = re.compile(
    r"arn:(?:aws|aws-us-gov|aws-cn):kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-fA-F-]{36}"
)
_PREFIX = re.compile(r"[A-Za-z0-9][A-Za-z0-9!_.*'()/=-]{0,255}")
_REGION = re.compile(r"[a-z]{2}(?:-gov)?-[a-z]+-[0-9]")
_VERSION_ID = re.compile(r"[\x21-\x7e]{1,1024}")

_RECEIPT_FIELDS = {
    "archived_at",
    "bucket_sha256",
    "bundle_sha256",
    "evidence_sha256",
    "kms_key_arn_sha256",
    "object_key",
    "retain_until",
    "schema_version",
    "version_id",
}
_BUNDLE_FIELDS = {
    "authorization",
    "baseline",
    "candidate",
    "gate_receipt",
    "release_epoch",
    "schema_version",
    "selector_key_status",
}

SignatureVerifier = Callable[[bytes, bytes, bytes], bool]
Clock = Callable[[], datetime]


class S3AuditClient(Protocol):
    """The read-only S3 surface required by the audit boundary."""

    def get_object(self, **kwargs: object) -> dict[str, Any]: ...

    def get_object_retention(self, **kwargs: object) -> dict[str, Any]: ...


ClientFactory = Callable[[], S3AuditClient]


class ReleaseArchiveAuditRejected(ValueError):
    """The receipt, stored object, retention, or replayed gate failed closed."""


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _utc_timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise ReleaseArchiveAuditRejected(f"{field} must be a UTC timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise ReleaseArchiveAuditRejected(f"{field} must be a UTC timestamp") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise ReleaseArchiveAuditRejected(f"{field} is not canonical")
    return parsed


def _validate_receipt(
    receipt: object,
    *,
    bucket: str,
    expected_bucket_owner: str,
    kms_key_arn: str,
    prefix: str,
) -> tuple[str, str, str, datetime]:
    if _BUCKET.fullmatch(bucket) is None or ".." in bucket:
        raise ReleaseArchiveAuditRejected("archive bucket name is invalid")
    if _ACCOUNT_ID.fullmatch(expected_bucket_owner) is None:
        raise ReleaseArchiveAuditRejected(
            "expected bucket owner must be a 12-digit account ID"
        )
    if (
        _KMS_KEY_ARN.fullmatch(kms_key_arn) is None
        or f":{expected_bucket_owner}:" not in kms_key_arn
    ):
        raise ReleaseArchiveAuditRejected(
            "KMS key must be a full key ARN in the bucket account"
        )
    if _PREFIX.fullmatch(prefix) is None or prefix.endswith("/"):
        raise ReleaseArchiveAuditRejected("archive prefix is invalid")
    if not isinstance(receipt, dict) or set(receipt) != _RECEIPT_FIELDS:
        raise ReleaseArchiveAuditRejected("archive receipt schema is invalid")
    if receipt.get("schema_version") != ARCHIVE_RECEIPT_SCHEMA:
        raise ReleaseArchiveAuditRejected("archive receipt version is unsupported")
    digest = receipt.get("evidence_sha256")
    unsigned = {
        key: value for key, value in receipt.items() if key != "evidence_sha256"
    }
    if (
        not isinstance(digest, str)
        or _HEX_SHA256.fullmatch(digest) is None
        or hashlib.sha256(_canonical(unsigned)).hexdigest() != digest
    ):
        raise ReleaseArchiveAuditRejected("archive receipt digest is invalid")
    bundle_digest = receipt.get("bundle_sha256")
    if (
        not isinstance(bundle_digest, str)
        or _HEX_SHA256.fullmatch(bundle_digest) is None
    ):
        raise ReleaseArchiveAuditRejected("archive bundle digest is invalid")
    if receipt.get("bucket_sha256") != _sha256_text(bucket):
        raise ReleaseArchiveAuditRejected("archive bucket commitment is mismatched")
    if receipt.get("kms_key_arn_sha256") != _sha256_text(kms_key_arn):
        raise ReleaseArchiveAuditRejected("archive KMS key commitment is mismatched")
    object_key = receipt.get("object_key")
    if object_key != f"{prefix}/{bundle_digest}.json":
        raise ReleaseArchiveAuditRejected("archive object key is not content addressed")
    version_id = receipt.get("version_id")
    if not isinstance(version_id, str) or _VERSION_ID.fullmatch(version_id) is None:
        raise ReleaseArchiveAuditRejected("archive version ID is invalid")
    archived_at = _utc_timestamp(receipt.get("archived_at"), "archived_at")
    retain_until = _utc_timestamp(receipt.get("retain_until"), "retain_until")
    if retain_until <= archived_at:
        raise ReleaseArchiveAuditRejected("archive retention interval is invalid")
    return bundle_digest, object_key, version_id, retain_until


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseArchiveAuditRejected("archive bundle contains duplicate keys")
        result[key] = value
    return result


def _read_body(response: dict[str, Any], expected_size: int) -> bytes:
    body = response.get("Body")
    if body is None or not callable(getattr(body, "read", None)):
        raise ReleaseArchiveAuditRejected("archive object body is unavailable")
    try:
        payload = body.read(MAX_ARCHIVE_BUNDLE_BYTES + 1)
    except Exception as exc:
        raise ReleaseArchiveAuditRejected("archive object body cannot be read") from exc
    finally:
        close = getattr(body, "close", None)
        if callable(close):
            close()
    if (
        not isinstance(payload, bytes)
        or len(payload) != expected_size
        or not 1 <= len(payload) <= MAX_ARCHIVE_BUNDLE_BYTES
    ):
        raise ReleaseArchiveAuditRejected("archive object body size is invalid")
    return payload


def audit_release_archive(
    receipt: object,
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
    client_factory: ClientFactory,
    signature_verifier: SignatureVerifier = verify_ed25519_signature,
    status_signature_verifier: SignatureVerifier = verify_ed25519_signature,
    release_signature_verifier: SignatureVerifier = verify_ed25519_signature,
    clock: Clock = lambda: datetime.now(UTC),
) -> dict[str, object]:
    """Recover an exact S3 version and independently replay its release gate."""
    bundle_digest, object_key, version_id, receipt_retain_until = _validate_receipt(
        receipt,
        bucket=bucket,
        expected_bucket_owner=expected_bucket_owner,
        kms_key_arn=kms_key_arn,
        prefix=prefix,
    )
    verified_at = clock()
    if verified_at.tzinfo is None or verified_at.utcoffset() is None:
        raise ReleaseArchiveAuditRejected("audit clock must return an aware datetime")
    verified_at = verified_at.astimezone(UTC)
    if verified_at >= receipt_retain_until:
        raise ReleaseArchiveAuditRejected("archive receipt retention has expired")

    try:
        client = client_factory()
    except Exception as exc:
        raise ReleaseArchiveAuditRejected("S3 audit client is unavailable") from exc
    request = {
        "Bucket": bucket,
        "Key": object_key,
        "VersionId": version_id,
        "ExpectedBucketOwner": expected_bucket_owner,
    }
    try:
        response = client.get_object(**request, ChecksumMode="ENABLED")
    except Exception as exc:
        raise ReleaseArchiveAuditRejected(
            "exact archive version cannot be recovered"
        ) from exc

    expected_checksum = base64.b64encode(bytes.fromhex(bundle_digest)).decode("ascii")
    size = response.get("ContentLength")
    if (
        isinstance(size, bool)
        or not isinstance(size, int)
        or not 1 <= size <= MAX_ARCHIVE_BUNDLE_BYTES
        or response.get("VersionId") != version_id
        or response.get("ContentType") != "application/json"
        or response.get("ChecksumSHA256") != expected_checksum
        or response.get("ServerSideEncryption") != "aws:kms"
        or response.get("SSEKMSKeyId") != kms_key_arn
        or response.get("BucketKeyEnabled") is not True
        or response.get("Metadata")
        != {"schema": ARCHIVE_BUNDLE_SCHEMA, "sha256": bundle_digest}
    ):
        raise ReleaseArchiveAuditRejected("archive object controls are mismatched")
    payload = _read_body(response, size)
    if hashlib.sha256(payload).hexdigest() != bundle_digest:
        raise ReleaseArchiveAuditRejected("archive object digest is mismatched")
    try:
        bundle = json.loads(payload, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseArchiveAuditRejected("archive bundle JSON is invalid") from exc
    if _canonical(bundle) != payload:
        raise ReleaseArchiveAuditRejected("archive bundle is not canonical JSON")
    if not isinstance(bundle, dict) or set(bundle) != _BUNDLE_FIELDS:
        raise ReleaseArchiveAuditRejected("archive bundle schema is invalid")
    if bundle.get("schema_version") != ARCHIVE_BUNDLE_SCHEMA:
        raise ReleaseArchiveAuditRejected("archive bundle version is unsupported")

    try:
        baseline = PartialLossBenchmarkEvidence.from_dict(bundle["baseline"])
        candidate = PartialLossBenchmarkEvidence.from_dict(bundle["candidate"])
        gate_receipt, comparison = gate_authorized_comparison(
            bundle["authorization"],
            bundle["selector_key_status"],
            bundle["release_epoch"],
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
    except (KeyError, TypeError, ValueError, RuntimeError) as exc:
        raise ReleaseArchiveAuditRejected(
            "archived release gate replay failed"
        ) from exc
    if comparison.accepted is not True or gate_receipt != bundle.get("gate_receipt"):
        raise ReleaseArchiveAuditRejected("archived release decision is mismatched")

    try:
        retention = client.get_object_retention(**request)
    except Exception as exc:
        raise ReleaseArchiveAuditRejected(
            "archive retention cannot be verified"
        ) from exc
    retained_until = retention.get("Retention", {}).get("RetainUntilDate")
    if (
        retention.get("Retention", {}).get("Mode") != "COMPLIANCE"
        or not isinstance(retained_until, datetime)
        or retained_until.tzinfo is None
    ):
        raise ReleaseArchiveAuditRejected("archive retention controls are invalid")
    retained_until = retained_until.astimezone(UTC)
    if retained_until < receipt_retain_until or verified_at >= retained_until:
        raise ReleaseArchiveAuditRejected("archive retention is shortened or expired")

    assert isinstance(receipt, dict)
    audit: dict[str, object] = {
        "archive_receipt_sha256": receipt["evidence_sha256"],
        "bundle_sha256": bundle_digest,
        "gate_receipt_sha256": gate_receipt["evidence_sha256"],
        "object_version_sha256": _sha256_text(version_id),
        "release_gate_replayed": True,
        "retain_until": retained_until.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "retention_mode": "COMPLIANCE",
        "schema_version": ARCHIVE_AUDIT_SCHEMA,
        "status": "pass",
        "storage_checksum_verified": True,
        "verified_at": verified_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    audit["evidence_sha256"] = hashlib.sha256(_canonical(audit)).hexdigest()
    return audit


def load_archive_receipt(path: Path) -> dict[str, object]:
    """Load one bounded regular JSON file without following symlinks."""
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ReleaseArchiveAuditRejected("archive receipt cannot be opened") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or not 1 <= metadata.st_size <= MAX_ARCHIVE_RECEIPT_BYTES
        ):
            raise ReleaseArchiveAuditRejected(
                "archive receipt must be a bounded regular file"
            )
        payload = os.read(descriptor, MAX_ARCHIVE_RECEIPT_BYTES + 1)
        if len(payload) != metadata.st_size:
            raise ReleaseArchiveAuditRejected(
                "archive receipt changed while being read"
            )
    finally:
        os.close(descriptor)
    try:
        result = json.loads(payload, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseArchiveAuditRejected("archive receipt JSON is invalid") from exc
    if not isinstance(result, dict):
        raise ReleaseArchiveAuditRejected("archive receipt must be a JSON object")
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Recover and independently audit an immutable netem release."
    )
    parser.add_argument("archive_receipt", type=Path)
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
            raise ReleaseArchiveAuditRejected("AWS region is invalid")
        if args.archive_receipt.resolve() == args.output.resolve():
            raise ReleaseArchiveAuditRejected("audit input and output must be distinct")

        def client_factory() -> S3AuditClient:
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

        audit = audit_release_archive(
            load_archive_receipt(args.archive_receipt),
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
            client_factory=client_factory,
            signature_verifier=verifier,
            status_signature_verifier=verifier,
            release_signature_verifier=verifier,
        )
        write_receipt(audit, args.output)
        return 0
    except (OSError, TypeError, ValueError, RuntimeError) as exc:
        print(f"release archive audit rejected: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
