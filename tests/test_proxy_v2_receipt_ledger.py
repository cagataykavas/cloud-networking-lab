from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest

from tools.proxy_v2_loopback import build_loopback_receipt
from tools.proxy_v2_receipt_ledger import (
    GENESIS_HEAD,
    _read_private_key,
    append_receipt,
    build_append_request,
    main,
    parse_append_request,
    parse_checkpoint,
    verify_ledger,
)

REQUEST_KEY = bytes(range(32))
CHECKPOINT_KEY = bytes(reversed(range(32)))
PAYLOAD = b"proxy-v2-application-frame\n"


def receipt(payload: bytes = PAYLOAD):
    return build_loopback_receipt(
        application_payload=payload,
        capacity_policy_sha256="1" * 64,
        proxy_policy_sha256="2" * 64,
        proxy_admission_evidence_sha256="3" * 64,
        connection_admission_evidence_sha256="4" * 64,
    )


def request(*, expected_head: str = GENESIS_HEAD, nonce: str = "run-1"):
    return build_append_request(
        receipt(),
        expected_head=expected_head,
        nonce=nonce,
        request_key=REQUEST_KEY,
        expected_payload=PAYLOAD,
    )


def test_appends_and_verifies_authenticated_hash_chain(tmp_path: Path) -> None:
    ledger = tmp_path / "receipts.jsonl"
    first = append_receipt(
        ledger,
        receipt(),
        request(),
        request_key=REQUEST_KEY,
        checkpoint_key=CHECKPOINT_KEY,
        expected_payload=PAYLOAD,
    )
    second_request = build_append_request(
        receipt(b"second-frame"),
        expected_head=first.ledger_head_sha256,
        nonce="run-2",
        request_key=REQUEST_KEY,
        expected_payload=b"second-frame",
    )
    second = append_receipt(
        ledger,
        receipt(b"second-frame"),
        second_request,
        request_key=REQUEST_KEY,
        checkpoint_key=CHECKPOINT_KEY,
        expected_payload=b"second-frame",
    )

    verify_ledger(
        ledger,
        second,
        request_key=REQUEST_KEY,
        checkpoint_key=CHECKPOINT_KEY,
        expected_head=second.ledger_head_sha256,
        minimum_entries=2,
    )
    lines = ledger.read_text(encoding="ascii").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[1])["previous_entry_sha256"] == first.ledger_head_sha256
    assert json.loads(lines[1])["sequence"] == 2
    assert second.entry_count == 2
    assert stat_mode(ledger) == 0o600


def test_wrong_key_and_tampered_request_fail_before_ledger_creation(
    tmp_path: Path,
) -> None:
    ledger = tmp_path / "receipts.jsonl"
    valid = request()

    with pytest.raises(ValueError, match="request_authentication_failed"):
        append_receipt(
            ledger,
            receipt(),
            valid,
            request_key=b"x" * 32,
            checkpoint_key=CHECKPOINT_KEY,
        )
    assert not ledger.exists()

    tampered = replace(valid, receipt_document_sha256="9" * 64)
    with pytest.raises(ValueError, match="request_receipt_mismatch"):
        append_receipt(
            ledger,
            receipt(),
            tampered,
            request_key=REQUEST_KEY,
            checkpoint_key=CHECKPOINT_KEY,
        )
    assert not ledger.exists()


def test_stale_head_and_duplicate_nonce_are_rejected_without_append(
    tmp_path: Path,
) -> None:
    ledger = tmp_path / "receipts.jsonl"
    first = append_receipt(
        ledger,
        receipt(),
        request(),
        request_key=REQUEST_KEY,
        checkpoint_key=CHECKPOINT_KEY,
    )
    original = ledger.read_bytes()

    with pytest.raises(ValueError, match="stale_ledger_head"):
        append_receipt(
            ledger,
            receipt(),
            request(expected_head=GENESIS_HEAD, nonce="run-2"),
            request_key=REQUEST_KEY,
            checkpoint_key=CHECKPOINT_KEY,
        )
    assert ledger.read_bytes() == original

    duplicate = request(expected_head=first.ledger_head_sha256, nonce="run-1")
    with pytest.raises(ValueError, match="duplicate_request_nonce"):
        append_receipt(
            ledger,
            receipt(),
            duplicate,
            request_key=REQUEST_KEY,
            checkpoint_key=CHECKPOINT_KEY,
        )
    assert ledger.read_bytes() == original


def test_file_lock_allows_only_one_concurrent_genesis_append(tmp_path: Path) -> None:
    ledger = tmp_path / "receipts.jsonl"
    requests = [request(nonce=f"run-{index}") for index in range(2)]

    def attempt(index: int) -> str:
        try:
            append_receipt(
                ledger,
                receipt(),
                requests[index],
                request_key=REQUEST_KEY,
                checkpoint_key=CHECKPOINT_KEY,
            )
        except ValueError as exc:
            return str(exc)
        return "accepted"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(attempt, range(2)))

    assert sorted(outcomes) == ["accepted", "stale_ledger_head"]
    assert len(ledger.read_text(encoding="ascii").splitlines()) == 1


def test_checkpoint_detects_deleted_tail_and_rollback(tmp_path: Path) -> None:
    ledger = tmp_path / "receipts.jsonl"
    first = append_receipt(
        ledger,
        receipt(),
        request(),
        request_key=REQUEST_KEY,
        checkpoint_key=CHECKPOINT_KEY,
    )
    first_payload = ledger.read_bytes()
    second_request = request(expected_head=first.ledger_head_sha256, nonce="run-2")
    second = append_receipt(
        ledger,
        receipt(),
        second_request,
        request_key=REQUEST_KEY,
        checkpoint_key=CHECKPOINT_KEY,
    )

    ledger.write_bytes(first_payload)
    os.chmod(ledger, 0o600)
    with pytest.raises(ValueError, match="checkpoint_ledger_mismatch"):
        verify_ledger(
            ledger,
            second,
            request_key=REQUEST_KEY,
            checkpoint_key=CHECKPOINT_KEY,
        )
    with pytest.raises(ValueError, match="ledger_head_mismatch"):
        verify_ledger(
            ledger,
            first,
            request_key=REQUEST_KEY,
            checkpoint_key=CHECKPOINT_KEY,
            expected_head=second.ledger_head_sha256,
        )


def test_middle_tampering_and_truncation_break_verification(tmp_path: Path) -> None:
    ledger = tmp_path / "receipts.jsonl"
    checkpoint = append_receipt(
        ledger,
        receipt(),
        request(),
        request_key=REQUEST_KEY,
        checkpoint_key=CHECKPOINT_KEY,
    )
    document = json.loads(ledger.read_text(encoding="ascii"))
    document["receipt"]["application_bytes"] += 1
    ledger.write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    )
    os.chmod(ledger, 0o600)

    with pytest.raises(ValueError, match="ledger_receipt_invalid"):
        verify_ledger(
            ledger,
            checkpoint,
            request_key=REQUEST_KEY,
            checkpoint_key=CHECKPOINT_KEY,
        )

    ledger.write_bytes(ledger.read_bytes()[:-1])
    with pytest.raises(ValueError, match="ledger_truncated"):
        verify_ledger(
            ledger,
            checkpoint,
            request_key=REQUEST_KEY,
            checkpoint_key=CHECKPOINT_KEY,
        )


def test_checkpoint_and_request_parsers_reject_ambiguous_json(tmp_path: Path) -> None:
    ledger = tmp_path / "receipts.jsonl"
    checkpoint = append_receipt(
        ledger,
        receipt(),
        request(),
        request_key=REQUEST_KEY,
        checkpoint_key=CHECKPOINT_KEY,
    )

    with pytest.raises(ValueError, match="duplicate_request_key"):
        parse_append_request(b'{"schema_version":1,"schema_version":1}')
    with pytest.raises(ValueError, match="checkpoint_fields_invalid"):
        parse_checkpoint(
            json.dumps({**checkpoint.as_dict(), "unexpected": True}).encode("ascii")
        )
    with pytest.raises(ValueError, match="checkpoint_authentication_failed"):
        verify_ledger(
            ledger,
            replace(checkpoint, hmac_sha256="f" * 64),
            request_key=REQUEST_KEY,
            checkpoint_key=CHECKPOINT_KEY,
        )
    with pytest.raises(ValueError, match="hmac_key_roles_not_distinct"):
        verify_ledger(
            ledger,
            checkpoint,
            request_key=REQUEST_KEY,
            checkpoint_key=REQUEST_KEY,
        )


def test_private_key_requires_bounded_regular_private_file(tmp_path: Path) -> None:
    key_file = tmp_path / "key"
    key_file.write_bytes(REQUEST_KEY)
    os.chmod(key_file, 0o600)
    assert _read_private_key(key_file) == REQUEST_KEY

    os.chmod(key_file, 0o640)
    with pytest.raises(ValueError, match="permissions_too_open"):
        _read_private_key(key_file)

    target = tmp_path / "target"
    target.write_bytes(REQUEST_KEY)
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="symlink_forbidden"):
        _read_private_key(link)


def test_ledger_refuses_symlinks_and_open_permissions(tmp_path: Path) -> None:
    target = tmp_path / "target.jsonl"
    target.write_bytes(b"")
    os.chmod(target, 0o600)
    link = tmp_path / "ledger.jsonl"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="ledger_symlink_forbidden"):
        append_receipt(
            link,
            receipt(),
            request(),
            request_key=REQUEST_KEY,
            checkpoint_key=CHECKPOINT_KEY,
        )

    open_ledger = tmp_path / "open.jsonl"
    open_ledger.write_bytes(b"")
    os.chmod(open_ledger, 0o644)
    with pytest.raises(ValueError, match="permissions_too_open"):
        append_receipt(
            open_ledger,
            receipt(),
            request(),
            request_key=REQUEST_KEY,
            checkpoint_key=CHECKPOINT_KEY,
        )

    missing = tmp_path / "missing.jsonl"
    with pytest.raises(ValueError, match="ledger_missing"):
        verify_ledger(
            missing,
            parse_checkpoint(
                json.dumps(
                    {
                        "entry_count": 1,
                        "hmac_sha256": "0" * 64,
                        "ledger_head_sha256": "0" * 64,
                        "ledger_sha256": "0" * 64,
                        "schema_version": 1,
                    }
                ).encode("ascii")
            ),
            request_key=REQUEST_KEY,
            checkpoint_key=CHECKPOINT_KEY,
        )
    assert not missing.exists()


def test_cli_round_trip_writes_private_evidence(tmp_path: Path) -> None:
    receipt_path = tmp_path / "receipt.json"
    request_path = tmp_path / "request.json"
    ledger_path = tmp_path / "ledger.jsonl"
    checkpoint_path = tmp_path / "checkpoint.json"
    request_key_path = tmp_path / "request-key"
    checkpoint_key_path = tmp_path / "checkpoint-key"
    receipt_path.write_text(
        json.dumps(receipt().as_dict(), sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )
    request_key_path.write_bytes(REQUEST_KEY)
    checkpoint_key_path.write_bytes(CHECKPOINT_KEY)
    os.chmod(request_key_path, 0o600)
    os.chmod(checkpoint_key_path, 0o600)

    request_key_args = ["--request-key-file", str(request_key_path)]
    append_key_args = [
        *request_key_args,
        "--checkpoint-key-file",
        str(checkpoint_key_path),
    ]
    payload_args = ["--payload-hex", PAYLOAD.hex()]
    assert (
        main(
            [
                "create-request",
                str(receipt_path),
                str(request_path),
                "--expected-head",
                GENESIS_HEAD,
                "--nonce",
                "ci-123-1",
                *request_key_args,
                *payload_args,
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "append",
                str(receipt_path),
                str(request_path),
                str(ledger_path),
                str(checkpoint_path),
                *append_key_args,
                *payload_args,
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "verify",
                str(ledger_path),
                str(checkpoint_path),
                *append_key_args,
                "--minimum-entries",
                "1",
            ]
        )
        == 0
    )
    assert stat_mode(request_path) == 0o600
    assert stat_mode(checkpoint_path) == 0o600
    assert stat_mode(ledger_path) == 0o600


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777
