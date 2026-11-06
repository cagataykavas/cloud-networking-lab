from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from tools.network_loss_release_epoch import (
    RELEASE_EPOCH_SCHEMA,
    ReleaseEpochRejected,
    create_release_epoch,
    load_release_epoch,
    verify_release_epoch,
)


AUTHORIZATION_SHA256 = "a" * 64
STATUS_SHA256 = "b" * 64
BASELINE_SHA256 = "c" * 64
CANDIDATE_SHA256 = "d" * 64
REPOSITORY_ID = "1330973695"
WORKFLOW_SHA = "e" * 40
SELECTOR_KEY = b"0" * 44
SELECTOR_KEY_SHA256 = hashlib.sha256(SELECTOR_KEY).hexdigest()
SELECTOR_KEY_ID = "netem-baseline-review-2026-11"
STATUS_KEY = b"1" * 44
STATUS_KEY_SHA256 = hashlib.sha256(STATUS_KEY).hexdigest()
STATUS_KEY_ID = "netem-selector-status-2026-11"
RELEASE_KEY = b"2" * 44
RELEASE_KEY_SHA256 = hashlib.sha256(RELEASE_KEY).hexdigest()
RELEASE_KEY_ID = "netem-release-epoch-2026-11"
RELEASE_SIGNATURE = b"r" * 64
RELEASED_AT = "2026-11-05T16:30:00Z"


def envelope(**overrides: object) -> dict[str, object]:
    parameters = {
        "authorization_sha256": AUTHORIZATION_SHA256,
        "selector_key_status_sha256": STATUS_SHA256,
        "baseline_benchmark_sha256": BASELINE_SHA256,
        "candidate_benchmark_sha256": CANDIDATE_SHA256,
        "repository_id": REPOSITORY_ID,
        "workflow_sha": WORKFLOW_SHA,
        "release_authority_key_id": RELEASE_KEY_ID,
        "released_at": RELEASED_AT,
        "public_key_der": RELEASE_KEY,
        "signer": lambda message: RELEASE_SIGNATURE if message else b"",
    }
    parameters.update(overrides)
    return create_release_epoch(**parameters)


def verify(document: object, **overrides: object) -> dict[str, object]:
    parameters = {
        "expected_authorization_sha256": AUTHORIZATION_SHA256,
        "expected_selector_key_status_sha256": STATUS_SHA256,
        "expected_baseline_benchmark_sha256": BASELINE_SHA256,
        "expected_candidate_benchmark_sha256": CANDIDATE_SHA256,
        "repository_id": REPOSITORY_ID,
        "workflow_sha": WORKFLOW_SHA,
        "expected_release_authority_key_id": RELEASE_KEY_ID,
        "expected_release_authority_public_key_sha256": RELEASE_KEY_SHA256,
        "selector_public_key_sha256": SELECTOR_KEY_SHA256,
        "status_authority_public_key_sha256": STATUS_KEY_SHA256,
        "selector_key_id": SELECTOR_KEY_ID,
        "status_authority_key_id": STATUS_KEY_ID,
        "signature_verifier": lambda public_key, signature, message: (
            public_key == RELEASE_KEY
            and signature == RELEASE_SIGNATURE
            and bool(message)
        ),
    }
    parameters.update(overrides)
    return verify_release_epoch(document, **parameters)


def test_verifies_exact_release_and_emits_private_commitments() -> None:
    document = envelope()
    receipt = verify(document)

    assert document["epoch"]["schema_version"] == RELEASE_EPOCH_SCHEMA
    assert receipt["released_at"] == RELEASED_AT
    assert receipt["release_authority_sha256"] == RELEASE_KEY_SHA256
    assert len(receipt["release_epoch_sha256"]) == 64
    retained = json.dumps(receipt, sort_keys=True)
    assert REPOSITORY_ID not in retained
    assert WORKFLOW_SHA not in retained
    assert RELEASE_KEY_ID not in retained
    assert document["signature"]["value"] not in retained
    assert document["public_key"]["value"] not in retained


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"expected_authorization_sha256": "0" * 64}, "requested gate"),
        ({"expected_selector_key_status_sha256": "0" * 64}, "requested gate"),
        ({"expected_baseline_benchmark_sha256": "0" * 64}, "requested gate"),
        ({"expected_candidate_benchmark_sha256": "0" * 64}, "requested gate"),
        ({"repository_id": "42"}, "requested gate"),
        ({"workflow_sha": "f" * 40}, "requested gate"),
        (
            {"expected_release_authority_key_id": "replacement-release"},
            "requested gate",
        ),
        (
            {"expected_release_authority_public_key_sha256": "0" * 64},
            "public-key pin",
        ),
    ],
)
def test_rejects_gate_or_authority_substitution(
    override: dict[str, object], message: str
) -> None:
    with pytest.raises(ReleaseEpochRejected, match=message):
        verify(envelope(), **override)


def test_rejects_release_key_or_key_id_role_reuse() -> None:
    with pytest.raises(ReleaseEpochRejected, match="key must be independent"):
        verify(
            envelope(public_key_der=SELECTOR_KEY),
            expected_release_authority_public_key_sha256=SELECTOR_KEY_SHA256,
        )

    with pytest.raises(ReleaseEpochRejected, match="key ID must be independent"):
        verify(
            envelope(release_authority_key_id=STATUS_KEY_ID),
            expected_release_authority_key_id=STATUS_KEY_ID,
        )


def test_signature_is_checked_before_untrusted_epoch_semantics() -> None:
    document = copy.deepcopy(envelope())
    document["epoch"]["released_at"] = "not-a-time"
    with pytest.raises(ReleaseEpochRejected, match="signature is invalid"):
        verify(document, signature_verifier=lambda *_: False)


def test_rejects_unknown_fields_noncanonical_base64_and_bad_signature() -> None:
    document = envelope()
    document["unexpected"] = True
    with pytest.raises(ReleaseEpochRejected, match="envelope fields"):
        verify(document)

    document = envelope()
    document["public_key"]["value"] += "\n"
    with pytest.raises(ReleaseEpochRejected, match="canonical base64"):
        verify(document)

    with pytest.raises(ReleaseEpochRejected, match="signature is invalid"):
        verify(envelope(), signature_verifier=lambda *_: False)


def test_creation_rejects_noncanonical_time_and_bad_signer() -> None:
    with pytest.raises(ReleaseEpochRejected, match="released_at"):
        envelope(released_at="2026-11-05T16:30:00+00:00")
    with pytest.raises(ReleaseEpochRejected, match="invalid signature"):
        envelope(signer=lambda _: b"short")


def test_loader_rejects_duplicate_keys_and_symlinks(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"epoch":{},"epoch":{}}', encoding="utf-8")
    with pytest.raises(ReleaseEpochRejected, match="duplicate"):
        load_release_epoch(duplicate)

    target = tmp_path / "release-epoch.json"
    target.write_text(json.dumps(envelope()), encoding="utf-8")
    link = tmp_path / "release-epoch-link.json"
    link.symlink_to(target)
    with pytest.raises(ReleaseEpochRejected, match="without following links"):
        load_release_epoch(link)
