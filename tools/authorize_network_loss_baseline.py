#!/usr/bin/env python3
"""Verify a signed baseline selection before releasing a netem regression gate."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tools.compare_network_loss_evidence import load_evidence, write_receipt
from tools.network_loss_selector_key_status import (
    SelectorKeyStatusRejected,
    load_selector_key_status,
    verify_selector_key_status,
)
from tools.network_loss_evidence import (
    PartialLossBenchmarkComparison,
    PartialLossBenchmarkEvidence,
    compare_partial_loss_benchmarks,
)


AUTHORIZATION_SCHEMA = "netem-baseline-authorization/v1"
GATE_SCHEMA = "netem-authorized-baseline-comparison/v2"
SIGNATURE_ALGORITHM = "Ed25519"
MAX_AUTHORIZATION_BYTES = 64 * 1024
MAX_AUTHORIZATION_LIFETIME = timedelta(hours=24)

_SHA256 = re.compile(r"[0-9a-f]{64}")
_SHA1 = re.compile(r"[0-9a-f]{40}")
_REPOSITORY_ID = re.compile(r"[1-9][0-9]{0,19}")
_KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}")
_TOP_LEVEL_FIELDS = frozenset({"authorization", "public_key", "signature"})
_AUTHORIZATION_FIELDS = frozenset(
    {
        "baseline_benchmark_sha256",
        "expires_at",
        "issued_at",
        "max_elapsed_increase_basis_points",
        "max_failure_rate_increase_basis_points",
        "policy_sha256",
        "repository_id",
        "runtime_fingerprint_sha256",
        "schema_version",
        "selector_key_id",
        "workflow_sha",
    }
)
_PUBLIC_KEY_FIELDS = frozenset({"encoding", "sha256", "value"})
_SIGNATURE_FIELDS = frozenset({"algorithm", "encoding", "value"})

SignatureVerifier = Callable[[bytes, bytes, bytes], bool]
Signer = Callable[[bytes], bytes]


class BaselineAuthorizationRejected(ValueError):
    """A baseline authorization is malformed, untrusted, stale, or mismatched."""


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _parse_time(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise BaselineAuthorizationRejected(
            f"{label} must be an RFC 3339 UTC timestamp"
        )
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise BaselineAuthorizationRejected(
            f"{label} must be an RFC 3339 UTC timestamp"
        ) from exc
    return parsed


def _validate_budget(value: object, label: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= 10_000
    ):
        raise BaselineAuthorizationRejected(f"{label} must be an integer in [0, 10000]")
    return value


def _canonical_base64(value: object, label: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise BaselineAuthorizationRejected(f"{label} must be canonical base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise BaselineAuthorizationRejected(
            f"{label} must be canonical base64"
        ) from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise BaselineAuthorizationRejected(f"{label} must be canonical base64")
    return decoded


def _authorization_claims(
    baseline: PartialLossBenchmarkEvidence,
    *,
    max_failure_rate_increase_basis_points: int,
    max_elapsed_increase_basis_points: int,
    repository_id: str,
    workflow_sha: str,
    selector_key_id: str,
    issued_at: str,
    expires_at: str,
) -> dict[str, object]:
    if not isinstance(baseline, PartialLossBenchmarkEvidence):
        raise BaselineAuthorizationRejected(
            "baseline must be validated benchmark evidence"
        )
    failure_budget = _validate_budget(
        max_failure_rate_increase_basis_points,
        "max_failure_rate_increase_basis_points",
    )
    elapsed_budget = _validate_budget(
        max_elapsed_increase_basis_points,
        "max_elapsed_increase_basis_points",
    )
    if _REPOSITORY_ID.fullmatch(repository_id) is None:
        raise BaselineAuthorizationRejected("repository_id is invalid")
    if _SHA1.fullmatch(workflow_sha) is None:
        raise BaselineAuthorizationRejected("workflow_sha is invalid")
    if _KEY_ID.fullmatch(selector_key_id) is None:
        raise BaselineAuthorizationRejected("selector_key_id is invalid")
    issued = _parse_time(issued_at, "issued_at")
    expires = _parse_time(expires_at, "expires_at")
    if not issued < expires <= issued + MAX_AUTHORIZATION_LIFETIME:
        raise BaselineAuthorizationRejected(
            "authorization lifetime must be positive and at most 24 hours"
        )
    baseline_comparison = compare_partial_loss_benchmarks(
        baseline,
        baseline,
        max_failure_rate_increase_basis_points=failure_budget,
        max_elapsed_increase_basis_points=elapsed_budget,
    )
    return {
        "baseline_benchmark_sha256": baseline.digest(),
        "expires_at": expires_at,
        "issued_at": issued_at,
        "max_elapsed_increase_basis_points": elapsed_budget,
        "max_failure_rate_increase_basis_points": failure_budget,
        "policy_sha256": baseline_comparison.policy_sha256,
        "repository_id": repository_id,
        "runtime_fingerprint_sha256": baseline.runtime_fingerprint.environment_sha256,
        "schema_version": AUTHORIZATION_SCHEMA,
        "selector_key_id": selector_key_id,
        "workflow_sha": workflow_sha,
    }


def create_baseline_authorization(
    baseline: PartialLossBenchmarkEvidence,
    *,
    max_failure_rate_increase_basis_points: int,
    max_elapsed_increase_basis_points: int,
    repository_id: str,
    workflow_sha: str,
    selector_key_id: str,
    issued_at: str,
    expires_at: str,
    public_key_der: bytes,
    signer: Signer,
) -> dict[str, object]:
    """Create a strict authorization envelope through an injected protected signer."""
    if not isinstance(public_key_der, bytes) or not 32 <= len(public_key_der) <= 4096:
        raise BaselineAuthorizationRejected("public key DER is outside the size limit")
    authorization = _authorization_claims(
        baseline,
        max_failure_rate_increase_basis_points=max_failure_rate_increase_basis_points,
        max_elapsed_increase_basis_points=max_elapsed_increase_basis_points,
        repository_id=repository_id,
        workflow_sha=workflow_sha,
        selector_key_id=selector_key_id,
        issued_at=issued_at,
        expires_at=expires_at,
    )
    signature = signer(_canonical(authorization))
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise BaselineAuthorizationRejected(
            "Ed25519 signer returned an invalid signature"
        )
    return {
        "authorization": authorization,
        "public_key": {
            "encoding": "base64-der-subject-public-key-info",
            "sha256": hashlib.sha256(public_key_der).hexdigest(),
            "value": base64.b64encode(public_key_der).decode("ascii"),
        },
        "signature": {
            "algorithm": SIGNATURE_ALGORITHM,
            "encoding": "base64",
            "value": base64.b64encode(signature).decode("ascii"),
        },
    }


def verify_ed25519_signature(
    public_key_der: bytes,
    signature: bytes,
    message: bytes,
    *,
    executable: str = "openssl",
    timeout_seconds: int = 10,
) -> bool:
    """Verify an Ed25519 signature through the OpenSSL command-line boundary."""
    if timeout_seconds < 1 or timeout_seconds > 60:
        raise ValueError("OpenSSL timeout must be in [1, 60] seconds")
    try:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public_key_path = root / "public-key.der"
            signature_path = root / "signature.bin"
            message_path = root / "message.bin"
            for path, payload in (
                (public_key_path, public_key_der),
                (signature_path, signature),
                (message_path, message),
            ):
                path.write_bytes(payload)
                path.chmod(0o600)
            completed = subprocess.run(
                [
                    executable,
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-keyform",
                    "DER",
                    "-inkey",
                    str(public_key_path),
                    "-rawin",
                    "-in",
                    str(message_path),
                    "-sigfile",
                    str(signature_path),
                ],
                check=False,
                capture_output=True,
                timeout=timeout_seconds,
            )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("OpenSSL Ed25519 verification is unavailable") from exc
    if completed.returncode == 0:
        return True
    if completed.returncode == 1:
        return False
    raise RuntimeError("OpenSSL rejected the Ed25519 verification request")


def verify_baseline_authorization(
    envelope: object,
    key_status_envelope: object,
    baseline: PartialLossBenchmarkEvidence,
    *,
    expected_public_key_sha256: str,
    expected_selector_key_id: str,
    expected_status_authority_public_key_sha256: str,
    expected_status_authority_key_id: str,
    repository_id: str,
    workflow_sha: str,
    verification_time: str,
    max_failure_rate_increase_basis_points: int,
    max_elapsed_increase_basis_points: int,
    signature_verifier: SignatureVerifier = verify_ed25519_signature,
    status_signature_verifier: SignatureVerifier = verify_ed25519_signature,
) -> dict[str, object]:
    """Verify the signature, trusted identity, freshness, and exact gate selection."""
    if not isinstance(envelope, dict) or set(envelope) != _TOP_LEVEL_FIELDS:
        raise BaselineAuthorizationRejected("authorization envelope fields are invalid")
    authorization = envelope.get("authorization")
    public_key = envelope.get("public_key")
    signature_document = envelope.get("signature")
    if (
        not isinstance(authorization, dict)
        or set(authorization) != _AUTHORIZATION_FIELDS
    ):
        raise BaselineAuthorizationRejected("authorization claim fields are invalid")
    if not isinstance(public_key, dict) or set(public_key) != _PUBLIC_KEY_FIELDS:
        raise BaselineAuthorizationRejected(
            "authorization public-key fields are invalid"
        )
    if (
        not isinstance(signature_document, dict)
        or set(signature_document) != _SIGNATURE_FIELDS
    ):
        raise BaselineAuthorizationRejected(
            "authorization signature fields are invalid"
        )
    if (
        public_key.get("encoding") != "base64-der-subject-public-key-info"
        or signature_document.get("encoding") != "base64"
        or signature_document.get("algorithm") != SIGNATURE_ALGORITHM
    ):
        raise BaselineAuthorizationRejected(
            "authorization cryptographic encoding is unsupported"
        )
    public_key_der = _canonical_base64(public_key.get("value"), "public key")
    signature = _canonical_base64(signature_document.get("value"), "signature")
    if len(signature) != 64:
        raise BaselineAuthorizationRejected("Ed25519 signature length is invalid")
    key_digest = hashlib.sha256(public_key_der).hexdigest()
    if (
        _SHA256.fullmatch(expected_public_key_sha256) is None
        or public_key.get("sha256") != key_digest
        or key_digest != expected_public_key_sha256
    ):
        raise BaselineAuthorizationRejected("selector public-key pin does not match")
    try:
        signature_valid = signature_verifier(
            public_key_der,
            signature,
            _canonical(authorization),
        )
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        raise BaselineAuthorizationRejected(
            "selector signature verification is unavailable"
        ) from exc
    if signature_valid is not True:
        raise BaselineAuthorizationRejected("selector signature is invalid")

    try:
        status_audit = verify_selector_key_status(
            key_status_envelope,
            expected_selector_key_id=expected_selector_key_id,
            expected_selector_public_key_sha256=key_digest,
            expected_status_authority_key_id=expected_status_authority_key_id,
            expected_status_authority_public_key_sha256=(
                expected_status_authority_public_key_sha256
            ),
            verification_time=verification_time,
            signature_verifier=status_signature_verifier,
        )
    except SelectorKeyStatusRejected as exc:
        raise BaselineAuthorizationRejected(str(exc)) from exc

    expected_claims = _authorization_claims(
        baseline,
        max_failure_rate_increase_basis_points=max_failure_rate_increase_basis_points,
        max_elapsed_increase_basis_points=max_elapsed_increase_basis_points,
        repository_id=repository_id,
        workflow_sha=workflow_sha,
        selector_key_id=expected_selector_key_id,
        issued_at=authorization.get("issued_at"),
        expires_at=authorization.get("expires_at"),
    )
    if authorization != expected_claims:
        raise BaselineAuthorizationRejected(
            "signed baseline selection does not match the requested gate"
        )
    verified_at = _parse_time(verification_time, "verification_time")
    issued_at = _parse_time(authorization["issued_at"], "issued_at")
    expires_at = _parse_time(authorization["expires_at"], "expires_at")
    if verified_at < issued_at:
        raise BaselineAuthorizationRejected("baseline authorization is not yet valid")
    if verified_at >= expires_at:
        raise BaselineAuthorizationRejected("baseline authorization has expired")
    binding = {
        "repository_id": repository_id,
        "workflow_sha": workflow_sha,
    }
    return {
        **status_audit,
        "authorization_sha256": hashlib.sha256(_canonical(envelope)).hexdigest(),
        "authorized_until": authorization["expires_at"],
        "baseline_benchmark_sha256": authorization["baseline_benchmark_sha256"],
        "policy_sha256": authorization["policy_sha256"],
        "runtime_fingerprint_sha256": authorization["runtime_fingerprint_sha256"],
        "selector_key_id_sha256": hashlib.sha256(
            expected_selector_key_id.encode("utf-8")
        ).hexdigest(),
        "selector_public_key_sha256": key_digest,
        "status": "authorized",
        "verified_at": verification_time,
        "workflow_binding_sha256": hashlib.sha256(_canonical(binding)).hexdigest(),
    }


def gate_authorized_comparison(
    envelope: object,
    key_status_envelope: object,
    baseline: PartialLossBenchmarkEvidence,
    candidate: PartialLossBenchmarkEvidence,
    *,
    expected_public_key_sha256: str,
    expected_selector_key_id: str,
    expected_status_authority_public_key_sha256: str,
    expected_status_authority_key_id: str,
    repository_id: str,
    workflow_sha: str,
    verification_time: str,
    max_failure_rate_increase_basis_points: int,
    max_elapsed_increase_basis_points: int,
    signature_verifier: SignatureVerifier = verify_ed25519_signature,
    status_signature_verifier: SignatureVerifier = verify_ed25519_signature,
) -> tuple[dict[str, object], PartialLossBenchmarkComparison]:
    """Authorize the exact baseline and budgets before comparing the candidate."""
    audit = verify_baseline_authorization(
        envelope,
        key_status_envelope,
        baseline,
        expected_public_key_sha256=expected_public_key_sha256,
        expected_selector_key_id=expected_selector_key_id,
        expected_status_authority_public_key_sha256=(
            expected_status_authority_public_key_sha256
        ),
        expected_status_authority_key_id=expected_status_authority_key_id,
        repository_id=repository_id,
        workflow_sha=workflow_sha,
        verification_time=verification_time,
        max_failure_rate_increase_basis_points=max_failure_rate_increase_basis_points,
        max_elapsed_increase_basis_points=max_elapsed_increase_basis_points,
        signature_verifier=signature_verifier,
        status_signature_verifier=status_signature_verifier,
    )
    comparison = compare_partial_loss_benchmarks(
        baseline,
        candidate,
        max_failure_rate_increase_basis_points=(max_failure_rate_increase_basis_points),
        max_elapsed_increase_basis_points=max_elapsed_increase_basis_points,
    )
    comparison_document = comparison.as_dict()
    receipt: dict[str, object] = {
        **audit,
        "candidate_benchmark_sha256": comparison.candidate_benchmark_sha256,
        "comparison_evidence_sha256": comparison_document["evidence_sha256"],
        "elapsed_change_basis_points": comparison.elapsed_change_basis_points,
        "failure_rate_delta_basis_points": (comparison.failure_rate_delta_basis_points),
        "schema_version": GATE_SCHEMA,
        "status": "pass" if comparison.accepted else "fail",
    }
    receipt["evidence_sha256"] = hashlib.sha256(_canonical(receipt)).hexdigest()
    return receipt, comparison


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise BaselineAuthorizationRejected(
                "authorization JSON contains duplicate keys"
            )
        document[key] = value
    return document


def load_authorization(path: Path) -> object:
    """Read one bounded authorization document without following a final symlink."""
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or not 1 <= metadata.st_size <= MAX_AUTHORIZATION_BYTES
        ):
            raise BaselineAuthorizationRejected(
                "authorization must be a bounded regular file"
            )
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(descriptor, 16 * 1024):
            size += len(chunk)
            if size > MAX_AUTHORIZATION_BYTES:
                raise BaselineAuthorizationRejected(
                    "authorization grew beyond the size limit"
                )
            chunks.append(chunk)
        payload = b"".join(chunks)
        if size != metadata.st_size:
            raise BaselineAuthorizationRejected(
                "authorization changed while being read"
            )
    except OSError as exc:
        raise BaselineAuthorizationRejected(
            "cannot read authorization without following links"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        return json.loads(payload, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BaselineAuthorizationRejected("authorization is not valid JSON") from exc


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Require signed baseline selection before a netem regression gate."
    )
    parser.add_argument("authorization", type=Path)
    parser.add_argument("selector_key_status", type=Path)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--selector-public-key-sha256", required=True)
    parser.add_argument("--selector-key-id", required=True)
    parser.add_argument("--status-authority-public-key-sha256", required=True)
    parser.add_argument("--status-authority-key-id", required=True)
    parser.add_argument("--repository-id", required=True)
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--verification-time")
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--timeout-seconds", type=int, default=10)
    parser.add_argument(
        "--max-failure-rate-increase-basis-points",
        type=int,
        default=250,
    )
    parser.add_argument(
        "--max-elapsed-increase-basis-points",
        type=int,
        default=2_000,
    )
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        inputs = {
            args.authorization.resolve(),
            args.selector_key_status.resolve(),
            args.baseline.resolve(),
            args.candidate.resolve(),
        }
        if len(inputs) != 4:
            raise BaselineAuthorizationRejected(
                "authorization, status, baseline, and candidate must be distinct files"
            )
        if args.output is not None and args.output.resolve() in inputs:
            raise BaselineAuthorizationRejected("output must not replace gate inputs")
        receipt, comparison = gate_authorized_comparison(
            load_authorization(args.authorization),
            load_selector_key_status(args.selector_key_status),
            load_evidence(args.baseline),
            load_evidence(args.candidate),
            expected_public_key_sha256=args.selector_public_key_sha256,
            expected_selector_key_id=args.selector_key_id,
            expected_status_authority_public_key_sha256=(
                args.status_authority_public_key_sha256
            ),
            expected_status_authority_key_id=args.status_authority_key_id,
            repository_id=args.repository_id,
            workflow_sha=args.workflow_sha,
            verification_time=args.verification_time or _now_utc(),
            max_failure_rate_increase_basis_points=(
                args.max_failure_rate_increase_basis_points
            ),
            max_elapsed_increase_basis_points=(args.max_elapsed_increase_basis_points),
            signature_verifier=lambda public_key, signature, message: (
                verify_ed25519_signature(
                    public_key,
                    signature,
                    message,
                    executable=args.openssl,
                    timeout_seconds=args.timeout_seconds,
                )
            ),
            status_signature_verifier=lambda public_key, signature, message: (
                verify_ed25519_signature(
                    public_key,
                    signature,
                    message,
                    executable=args.openssl,
                    timeout_seconds=args.timeout_seconds,
                )
            ),
        )
        if args.output is None:
            print(json.dumps(receipt, allow_nan=False, indent=2, sort_keys=True))
        else:
            write_receipt(receipt, args.output)
        return 0 if comparison.accepted else 3
    except (OSError, TypeError, ValueError, RuntimeError) as exc:
        print(f"authorized benchmark comparison rejected: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
