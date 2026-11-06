#!/usr/bin/env python3
"""Issue and verify short-lived status for a netem baseline selector key."""

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
from datetime import datetime, timedelta, timezone
from pathlib import Path


STATUS_SCHEMA = "netem-selector-key-status/v1"
SIGNATURE_ALGORITHM = "Ed25519"
MAX_STATUS_BYTES = 32 * 1024
MAX_STATUS_LIFETIME = timedelta(hours=24)

_SHA256 = re.compile(r"[0-9a-f]{64}")
_KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}")
_TOP_LEVEL_FIELDS = frozenset({"authority_public_key", "signature", "status"})
_STATUS_FIELDS = frozenset(
    {
        "expires_at",
        "issued_at",
        "schema_version",
        "selector_key_id",
        "selector_public_key_sha256",
        "state",
        "status_authority_key_id",
    }
)
_PUBLIC_KEY_FIELDS = frozenset({"encoding", "sha256", "value"})
_SIGNATURE_FIELDS = frozenset({"algorithm", "encoding", "value"})

SignatureVerifier = Callable[[bytes, bytes, bytes], bool]
Signer = Callable[[bytes], bytes]


class SelectorKeyStatusRejected(ValueError):
    """A selector-key status snapshot is malformed, untrusted, stale, or revoked."""


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
        raise SelectorKeyStatusRejected(f"{label} must be an RFC 3339 UTC timestamp")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise SelectorKeyStatusRejected(
            f"{label} must be an RFC 3339 UTC timestamp"
        ) from exc


def _canonical_base64(value: object, label: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise SelectorKeyStatusRejected(f"{label} must be canonical base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SelectorKeyStatusRejected(f"{label} must be canonical base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise SelectorKeyStatusRejected(f"{label} must be canonical base64")
    return decoded


def _status_claims(
    *,
    selector_key_id: str,
    selector_public_key_sha256: str,
    state: str,
    status_authority_key_id: str,
    issued_at: str,
    expires_at: str,
) -> dict[str, object]:
    if _KEY_ID.fullmatch(selector_key_id) is None:
        raise SelectorKeyStatusRejected("selector_key_id is invalid")
    if _SHA256.fullmatch(selector_public_key_sha256) is None:
        raise SelectorKeyStatusRejected("selector_public_key_sha256 is invalid")
    if state not in {"active", "revoked"}:
        raise SelectorKeyStatusRejected("selector key state is invalid")
    if _KEY_ID.fullmatch(status_authority_key_id) is None:
        raise SelectorKeyStatusRejected("status_authority_key_id is invalid")
    issued = _parse_time(issued_at, "issued_at")
    expires = _parse_time(expires_at, "expires_at")
    if not issued < expires <= issued + MAX_STATUS_LIFETIME:
        raise SelectorKeyStatusRejected(
            "selector key status lifetime must be positive and at most 24 hours"
        )
    return {
        "expires_at": expires_at,
        "issued_at": issued_at,
        "schema_version": STATUS_SCHEMA,
        "selector_key_id": selector_key_id,
        "selector_public_key_sha256": selector_public_key_sha256,
        "state": state,
        "status_authority_key_id": status_authority_key_id,
    }


def create_selector_key_status(
    *,
    selector_key_id: str,
    selector_public_key_sha256: str,
    state: str,
    status_authority_key_id: str,
    issued_at: str,
    expires_at: str,
    authority_public_key_der: bytes,
    signer: Signer,
) -> dict[str, object]:
    """Create one canonical status envelope through an injected protected signer."""
    if (
        not isinstance(authority_public_key_der, bytes)
        or not 32 <= len(authority_public_key_der) <= 4096
    ):
        raise SelectorKeyStatusRejected(
            "status authority public key DER is outside the size limit"
        )
    authority_digest = hashlib.sha256(authority_public_key_der).hexdigest()
    if authority_digest == selector_public_key_sha256:
        raise SelectorKeyStatusRejected(
            "status authority key must be independent from the selector key"
        )
    status = _status_claims(
        selector_key_id=selector_key_id,
        selector_public_key_sha256=selector_public_key_sha256,
        state=state,
        status_authority_key_id=status_authority_key_id,
        issued_at=issued_at,
        expires_at=expires_at,
    )
    signature = signer(_canonical(status))
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise SelectorKeyStatusRejected(
            "Ed25519 status signer returned an invalid signature"
        )
    return {
        "authority_public_key": {
            "encoding": "base64-der-subject-public-key-info",
            "sha256": authority_digest,
            "value": base64.b64encode(authority_public_key_der).decode("ascii"),
        },
        "signature": {
            "algorithm": SIGNATURE_ALGORITHM,
            "encoding": "base64",
            "value": base64.b64encode(signature).decode("ascii"),
        },
        "status": status,
    }


def verify_selector_key_status(
    envelope: object,
    *,
    expected_selector_key_id: str,
    expected_selector_public_key_sha256: str,
    expected_status_authority_key_id: str,
    expected_status_authority_public_key_sha256: str,
    verification_time: str,
    signature_verifier: SignatureVerifier,
) -> dict[str, object]:
    """Verify an independent status signature and require a fresh active key."""
    if not isinstance(envelope, dict) or set(envelope) != _TOP_LEVEL_FIELDS:
        raise SelectorKeyStatusRejected(
            "selector key status envelope fields are invalid"
        )
    status = envelope.get("status")
    public_key = envelope.get("authority_public_key")
    signature_document = envelope.get("signature")
    if not isinstance(status, dict) or set(status) != _STATUS_FIELDS:
        raise SelectorKeyStatusRejected("selector key status claim fields are invalid")
    if not isinstance(public_key, dict) or set(public_key) != _PUBLIC_KEY_FIELDS:
        raise SelectorKeyStatusRejected(
            "status authority public-key fields are invalid"
        )
    if (
        not isinstance(signature_document, dict)
        or set(signature_document) != _SIGNATURE_FIELDS
    ):
        raise SelectorKeyStatusRejected("status signature fields are invalid")
    if (
        public_key.get("encoding") != "base64-der-subject-public-key-info"
        or signature_document.get("encoding") != "base64"
        or signature_document.get("algorithm") != SIGNATURE_ALGORITHM
    ):
        raise SelectorKeyStatusRejected("status cryptographic encoding is unsupported")
    authority_key = _canonical_base64(
        public_key.get("value"), "status authority public key"
    )
    signature = _canonical_base64(signature_document.get("value"), "status signature")
    if len(signature) != 64:
        raise SelectorKeyStatusRejected("Ed25519 status signature length is invalid")
    authority_digest = hashlib.sha256(authority_key).hexdigest()
    if (
        _SHA256.fullmatch(expected_status_authority_public_key_sha256) is None
        or public_key.get("sha256") != authority_digest
        or authority_digest != expected_status_authority_public_key_sha256
    ):
        raise SelectorKeyStatusRejected(
            "status authority public-key pin does not match"
        )
    if authority_digest == expected_selector_public_key_sha256:
        raise SelectorKeyStatusRejected(
            "status authority key must be independent from the selector key"
        )
    try:
        signature_valid = signature_verifier(
            authority_key,
            signature,
            _canonical(status),
        )
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        raise SelectorKeyStatusRejected(
            "status signature verification is unavailable"
        ) from exc
    if signature_valid is not True:
        raise SelectorKeyStatusRejected("status signature is invalid")

    expected_status = _status_claims(
        selector_key_id=expected_selector_key_id,
        selector_public_key_sha256=expected_selector_public_key_sha256,
        state=status.get("state"),
        status_authority_key_id=expected_status_authority_key_id,
        issued_at=status.get("issued_at"),
        expires_at=status.get("expires_at"),
    )
    if status != expected_status:
        raise SelectorKeyStatusRejected(
            "signed selector key status does not match the requested gate"
        )
    verified_at = _parse_time(verification_time, "verification_time")
    issued_at = _parse_time(status["issued_at"], "issued_at")
    expires_at = _parse_time(status["expires_at"], "expires_at")
    if verified_at < issued_at:
        raise SelectorKeyStatusRejected("selector key status is not yet valid")
    if verified_at >= expires_at:
        raise SelectorKeyStatusRejected("selector key status has expired")
    if status["state"] != "active":
        raise SelectorKeyStatusRejected("selector key is revoked")
    return {
        "selector_key_status_sha256": hashlib.sha256(_canonical(envelope)).hexdigest(),
        "selector_status_authority_sha256": authority_digest,
        "selector_status_valid_until": status["expires_at"],
    }


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise SelectorKeyStatusRejected(
                "selector key status contains duplicate keys"
            )
        document[key] = value
    return document


def load_selector_key_status(path: Path) -> object:
    """Read one bounded status document without following a final symlink."""
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or not 1 <= metadata.st_size <= MAX_STATUS_BYTES
        ):
            raise SelectorKeyStatusRejected(
                "selector key status must be a bounded regular file"
            )
        payload = b""
        while chunk := os.read(descriptor, 8192):
            payload += chunk
            if len(payload) > MAX_STATUS_BYTES:
                raise SelectorKeyStatusRejected(
                    "selector key status grew beyond the size limit"
                )
        if len(payload) != metadata.st_size:
            raise SelectorKeyStatusRejected(
                "selector key status changed while being read"
            )
    except OSError as exc:
        raise SelectorKeyStatusRejected(
            "cannot read selector key status without following links"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        return json.loads(payload, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SelectorKeyStatusRejected(
            "selector key status is not valid JSON"
        ) from exc
