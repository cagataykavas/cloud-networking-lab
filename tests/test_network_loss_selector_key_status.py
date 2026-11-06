from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from tools.network_loss_selector_key_status import (
    STATUS_SCHEMA,
    SelectorKeyStatusRejected,
    create_selector_key_status,
    load_selector_key_status,
    verify_selector_key_status,
)


SELECTOR_KEY = b"0" * 44
SELECTOR_KEY_SHA256 = hashlib.sha256(SELECTOR_KEY).hexdigest()
SELECTOR_KEY_ID = "netem-baseline-review-2026-11"
AUTHORITY_KEY = b"1" * 44
AUTHORITY_KEY_SHA256 = hashlib.sha256(AUTHORITY_KEY).hexdigest()
AUTHORITY_KEY_ID = "netem-selector-status-2026-11"
SIGNATURE = b"s" * 64
ISSUED_AT = "2026-11-05T16:00:00Z"
EXPIRES_AT = "2026-11-05T17:00:00Z"
VERIFICATION_TIME = "2026-11-05T16:30:00Z"


def envelope(**overrides: object) -> dict[str, object]:
    parameters = {
        "selector_key_id": SELECTOR_KEY_ID,
        "selector_public_key_sha256": SELECTOR_KEY_SHA256,
        "state": "active",
        "status_authority_key_id": AUTHORITY_KEY_ID,
        "issued_at": ISSUED_AT,
        "expires_at": EXPIRES_AT,
        "authority_public_key_der": AUTHORITY_KEY,
        "signer": lambda message: SIGNATURE if message else b"",
    }
    parameters.update(overrides)
    return create_selector_key_status(**parameters)


def verify(document: object, **overrides: object) -> dict[str, object]:
    parameters = {
        "expected_selector_key_id": SELECTOR_KEY_ID,
        "expected_selector_public_key_sha256": SELECTOR_KEY_SHA256,
        "expected_status_authority_key_id": AUTHORITY_KEY_ID,
        "expected_status_authority_public_key_sha256": AUTHORITY_KEY_SHA256,
        "verification_time": VERIFICATION_TIME,
        "signature_verifier": lambda public_key, signature, message: (
            public_key == AUTHORITY_KEY and signature == SIGNATURE and bool(message)
        ),
    }
    parameters.update(overrides)
    return verify_selector_key_status(document, **parameters)


def test_verifies_fresh_active_status_and_emits_private_commitments() -> None:
    document = envelope()
    receipt = verify(document)

    assert document["status"]["schema_version"] == STATUS_SCHEMA
    assert receipt["selector_status_valid_until"] == EXPIRES_AT
    assert len(receipt["selector_key_status_sha256"]) == 64
    assert receipt["selector_status_authority_sha256"] == AUTHORITY_KEY_SHA256
    retained = json.dumps(receipt, sort_keys=True)
    assert SELECTOR_KEY_ID not in retained
    assert AUTHORITY_KEY_ID not in retained
    assert document["signature"]["value"] not in retained
    assert document["authority_public_key"]["value"] not in retained


def test_rejects_revoked_selector_key() -> None:
    with pytest.raises(SelectorKeyStatusRejected, match="revoked"):
        verify(envelope(state="revoked"))


@pytest.mark.parametrize(
    ("override", "message"),
    [
        (
            {"expected_status_authority_public_key_sha256": "f" * 64},
            "authority public-key pin",
        ),
        (
            {"expected_status_authority_key_id": "replacement-authority"},
            "requested gate",
        ),
        (
            {"expected_selector_key_id": "replacement-selector"},
            "requested gate",
        ),
        (
            {"expected_selector_public_key_sha256": "e" * 64},
            "requested gate",
        ),
    ],
)
def test_rejects_authority_or_selector_substitution(
    override: dict[str, object], message: str
) -> None:
    with pytest.raises(SelectorKeyStatusRejected, match=message):
        verify(envelope(), **override)


@pytest.mark.parametrize(
    ("verification_time", "message"),
    [
        ("2026-11-05T15:59:59Z", "not yet valid"),
        (EXPIRES_AT, "expired"),
        ("2026-11-05T18:00:00Z", "expired"),
    ],
)
def test_rejects_status_outside_its_validity_window(
    verification_time: str, message: str
) -> None:
    with pytest.raises(SelectorKeyStatusRejected, match=message):
        verify(envelope(), verification_time=verification_time)


def test_rejects_overlong_status_and_key_role_reuse() -> None:
    with pytest.raises(SelectorKeyStatusRejected, match="at most 24 hours"):
        envelope(expires_at="2026-11-06T16:00:01Z")

    with pytest.raises(SelectorKeyStatusRejected, match="independent"):
        envelope(
            selector_public_key_sha256=AUTHORITY_KEY_SHA256,
            authority_public_key_der=AUTHORITY_KEY,
        )


def test_signature_is_checked_before_untrusted_status_semantics() -> None:
    document = copy.deepcopy(envelope())
    document["status"]["state"] = "unknown"
    with pytest.raises(SelectorKeyStatusRejected, match="signature is invalid"):
        verify(document, signature_verifier=lambda *_: False)


def test_rejects_unknown_fields_noncanonical_base64_and_bad_signature() -> None:
    document = envelope()
    document["unexpected"] = True
    with pytest.raises(SelectorKeyStatusRejected, match="envelope fields"):
        verify(document)

    document = envelope()
    document["authority_public_key"]["value"] += "\n"
    with pytest.raises(SelectorKeyStatusRejected, match="canonical base64"):
        verify(document)

    with pytest.raises(SelectorKeyStatusRejected, match="signature is invalid"):
        verify(envelope(), signature_verifier=lambda *_: False)


def test_loader_rejects_duplicate_keys_and_symlinks(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"status":{},"status":{}}', encoding="utf-8")
    with pytest.raises(SelectorKeyStatusRejected, match="duplicate"):
        load_selector_key_status(duplicate)

    target = tmp_path / "status.json"
    target.write_text(json.dumps(envelope()), encoding="utf-8")
    link = tmp_path / "status-link.json"
    link.symlink_to(target)
    with pytest.raises(SelectorKeyStatusRejected, match="without following links"):
        load_selector_key_status(link)
