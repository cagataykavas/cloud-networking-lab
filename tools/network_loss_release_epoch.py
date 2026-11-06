#!/usr/bin/env python3
"""Issue and verify authenticated release time for one exact netem gate."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import stat
import subprocess
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path


RELEASE_EPOCH_SCHEMA = "netem-release-epoch/v1"
SIGNATURE_ALGORITHM = "Ed25519"
MAX_RELEASE_EPOCH_BYTES = 32 * 1024

_SHA256 = re.compile(r"[0-9a-f]{64}")
_SHA1 = re.compile(r"[0-9a-f]{40}")
_REPOSITORY_ID = re.compile(r"[1-9][0-9]{0,19}")
_KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}")
_TOP_LEVEL_FIELDS = frozenset({"epoch", "public_key", "signature"})
_EPOCH_FIELDS = frozenset(
    {
        "authorization_sha256",
        "baseline_benchmark_sha256",
        "candidate_benchmark_sha256",
        "release_authority_key_id",
        "released_at",
        "repository_id",
        "schema_version",
        "selector_key_status_sha256",
        "workflow_sha",
    }
)
_PUBLIC_KEY_FIELDS = frozenset({"encoding", "sha256", "value"})
_SIGNATURE_FIELDS = frozenset({"algorithm", "encoding", "value"})

SignatureVerifier = Callable[[bytes, bytes, bytes], bool]
Signer = Callable[[bytes], bytes]


class ReleaseEpochRejected(ValueError):
    """The release epoch is malformed, untrusted, or bound to another gate."""


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ReleaseEpochRejected(f"{label} is not a SHA-256 digest")
    return value


def _time(value: object) -> str:
    if not isinstance(value, str):
        raise ReleaseEpochRejected("released_at must be an RFC 3339 UTC timestamp")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ReleaseEpochRejected(
            "released_at must be an RFC 3339 UTC timestamp"
        ) from exc
    return value


def _canonical_base64(value: object, label: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ReleaseEpochRejected(f"{label} must be canonical base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ReleaseEpochRejected(f"{label} must be canonical base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ReleaseEpochRejected(f"{label} must be canonical base64")
    return decoded


def _claims(
    *,
    authorization_sha256: str,
    selector_key_status_sha256: str,
    baseline_benchmark_sha256: str,
    candidate_benchmark_sha256: str,
    repository_id: str,
    workflow_sha: str,
    release_authority_key_id: str,
    released_at: str,
) -> dict[str, object]:
    claims = {
        "authorization_sha256": _digest(authorization_sha256, "authorization_sha256"),
        "baseline_benchmark_sha256": _digest(
            baseline_benchmark_sha256, "baseline_benchmark_sha256"
        ),
        "candidate_benchmark_sha256": _digest(
            candidate_benchmark_sha256, "candidate_benchmark_sha256"
        ),
        "selector_key_status_sha256": _digest(
            selector_key_status_sha256, "selector_key_status_sha256"
        ),
    }
    if _REPOSITORY_ID.fullmatch(repository_id) is None:
        raise ReleaseEpochRejected("repository_id is invalid")
    if _SHA1.fullmatch(workflow_sha) is None:
        raise ReleaseEpochRejected("workflow_sha is invalid")
    if _KEY_ID.fullmatch(release_authority_key_id) is None:
        raise ReleaseEpochRejected("release_authority_key_id is invalid")
    return {
        **claims,
        "release_authority_key_id": release_authority_key_id,
        "released_at": _time(released_at),
        "repository_id": repository_id,
        "schema_version": RELEASE_EPOCH_SCHEMA,
        "workflow_sha": workflow_sha,
    }


def create_release_epoch(
    *,
    authorization_sha256: str,
    selector_key_status_sha256: str,
    baseline_benchmark_sha256: str,
    candidate_benchmark_sha256: str,
    repository_id: str,
    workflow_sha: str,
    release_authority_key_id: str,
    released_at: str,
    public_key_der: bytes,
    signer: Signer,
) -> dict[str, object]:
    """Create one exact release epoch through an injected protected signer."""
    if not isinstance(public_key_der, bytes) or not 32 <= len(public_key_der) <= 4096:
        raise ReleaseEpochRejected(
            "release authority public key is outside the size limit"
        )
    epoch = _claims(
        authorization_sha256=authorization_sha256,
        selector_key_status_sha256=selector_key_status_sha256,
        baseline_benchmark_sha256=baseline_benchmark_sha256,
        candidate_benchmark_sha256=candidate_benchmark_sha256,
        repository_id=repository_id,
        workflow_sha=workflow_sha,
        release_authority_key_id=release_authority_key_id,
        released_at=released_at,
    )
    signature = signer(_canonical(epoch))
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise ReleaseEpochRejected(
            "Ed25519 release signer returned an invalid signature"
        )
    return {
        "epoch": epoch,
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


def verify_release_epoch(
    envelope: object,
    *,
    expected_authorization_sha256: str,
    expected_selector_key_status_sha256: str,
    expected_baseline_benchmark_sha256: str,
    expected_candidate_benchmark_sha256: str,
    repository_id: str,
    workflow_sha: str,
    expected_release_authority_key_id: str,
    expected_release_authority_public_key_sha256: str,
    selector_public_key_sha256: str,
    status_authority_public_key_sha256: str,
    selector_key_id: str,
    status_authority_key_id: str,
    signature_verifier: SignatureVerifier,
) -> dict[str, object]:
    """Verify signed release time and bind it to one exact gate invocation."""
    if not isinstance(envelope, dict) or set(envelope) != _TOP_LEVEL_FIELDS:
        raise ReleaseEpochRejected("release epoch envelope fields are invalid")
    epoch = envelope.get("epoch")
    public_key = envelope.get("public_key")
    signature_document = envelope.get("signature")
    if not isinstance(epoch, dict) or set(epoch) != _EPOCH_FIELDS:
        raise ReleaseEpochRejected("release epoch claim fields are invalid")
    if not isinstance(public_key, dict) or set(public_key) != _PUBLIC_KEY_FIELDS:
        raise ReleaseEpochRejected("release authority public-key fields are invalid")
    if (
        not isinstance(signature_document, dict)
        or set(signature_document) != _SIGNATURE_FIELDS
    ):
        raise ReleaseEpochRejected("release epoch signature fields are invalid")
    if (
        public_key.get("encoding") != "base64-der-subject-public-key-info"
        or signature_document.get("encoding") != "base64"
        or signature_document.get("algorithm") != SIGNATURE_ALGORITHM
    ):
        raise ReleaseEpochRejected(
            "release epoch cryptographic encoding is unsupported"
        )
    release_key = _canonical_base64(public_key.get("value"), "release public key")
    signature = _canonical_base64(signature_document.get("value"), "release signature")
    if len(signature) != 64:
        raise ReleaseEpochRejected("Ed25519 release signature length is invalid")
    release_digest = hashlib.sha256(release_key).hexdigest()
    if (
        _SHA256.fullmatch(expected_release_authority_public_key_sha256) is None
        or public_key.get("sha256") != release_digest
        or release_digest != expected_release_authority_public_key_sha256
    ):
        raise ReleaseEpochRejected("release authority public-key pin does not match")
    if release_digest in {
        _digest(selector_public_key_sha256, "selector_public_key_sha256"),
        _digest(
            status_authority_public_key_sha256, "status_authority_public_key_sha256"
        ),
    }:
        raise ReleaseEpochRejected(
            "release authority key must be independent from selector and status keys"
        )
    if expected_release_authority_key_id in {selector_key_id, status_authority_key_id}:
        raise ReleaseEpochRejected(
            "release authority key ID must be independent from selector and status keys"
        )
    try:
        signature_valid = signature_verifier(release_key, signature, _canonical(epoch))
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        raise ReleaseEpochRejected(
            "release signature verification is unavailable"
        ) from exc
    if signature_valid is not True:
        raise ReleaseEpochRejected("release signature is invalid")
    expected = _claims(
        authorization_sha256=expected_authorization_sha256,
        selector_key_status_sha256=expected_selector_key_status_sha256,
        baseline_benchmark_sha256=expected_baseline_benchmark_sha256,
        candidate_benchmark_sha256=expected_candidate_benchmark_sha256,
        repository_id=repository_id,
        workflow_sha=workflow_sha,
        release_authority_key_id=expected_release_authority_key_id,
        released_at=epoch.get("released_at"),
    )
    if epoch != expected:
        raise ReleaseEpochRejected(
            "signed release epoch does not match the requested gate"
        )
    return {
        "release_authority_sha256": release_digest,
        "release_epoch_sha256": hashlib.sha256(_canonical(envelope)).hexdigest(),
        "released_at": epoch["released_at"],
    }


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise ReleaseEpochRejected("release epoch contains duplicate keys")
        document[key] = value
    return document


def load_release_epoch(path: Path) -> object:
    """Read one bounded release epoch without following or racing a final link."""
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not 1 <= before.st_size <= MAX_RELEASE_EPOCH_BYTES
        ):
            raise ReleaseEpochRejected("release epoch must be a bounded regular file")
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(descriptor, 8192):
            size += len(chunk)
            if size > MAX_RELEASE_EPOCH_BYTES:
                raise ReleaseEpochRejected("release epoch grew beyond the size limit")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (
            size != before.st_size
            or after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns
            or after.st_ctime_ns != before.st_ctime_ns
        ):
            raise ReleaseEpochRejected("release epoch changed while being read")
    except OSError as exc:
        raise ReleaseEpochRejected(
            "cannot read release epoch without following links"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        return json.loads(b"".join(chunks), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseEpochRejected("release epoch is not valid JSON") from exc
