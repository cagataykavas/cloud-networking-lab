from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

import tools.authorize_network_loss_baseline as authorization_module
from tools.authorize_network_loss_baseline import (
    AUTHORIZATION_SCHEMA,
    GATE_SCHEMA,
    BaselineAuthorizationRejected,
    create_baseline_authorization,
    gate_authorized_comparison,
    load_authorization,
    main,
    verify_baseline_authorization,
)
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
from tools.network_loss_selector_key_status import create_selector_key_status


PUBLIC_KEY = b"0" * 44
SIGNATURE = b"s" * 64
PUBLIC_KEY_SHA256 = hashlib.sha256(PUBLIC_KEY).hexdigest()
KEY_ID = "netem-baseline-review-2026-11"
STATUS_AUTHORITY_PUBLIC_KEY = b"1" * 44
STATUS_AUTHORITY_SIGNATURE = b"t" * 64
STATUS_AUTHORITY_PUBLIC_KEY_SHA256 = hashlib.sha256(
    STATUS_AUTHORITY_PUBLIC_KEY
).hexdigest()
STATUS_AUTHORITY_KEY_ID = "netem-selector-status-2026-11"
REPOSITORY_ID = "1330973695"
WORKFLOW_SHA = "a" * 40
ISSUED_AT = "2026-11-05T16:00:00Z"
EXPIRES_AT = "2026-11-05T17:00:00Z"
VERIFICATION_TIME = "2026-11-05T16:30:00Z"
FAILURE_BUDGET = 250
ELAPSED_BUDGET = 2_000


def fingerprint(kernel: str = "a" * 64, tc: str = "b" * 64) -> NetemRuntimeFingerprint:
    payload = json.dumps(
        {
            "kernel_release_sha256": kernel,
            "schema_version": RUNTIME_FINGERPRINT_SCHEMA,
            "tc_version_sha256": tc,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return NetemRuntimeFingerprint(
        kernel_release_sha256=kernel,
        tc_version_sha256=tc,
        environment_sha256=hashlib.sha256(payload).hexdigest(),
    )


def benchmark(
    *,
    failures: int = 4,
    elapsed_ms: int = 700,
    runtime: NetemRuntimeFingerprint | None = None,
) -> PartialLossBenchmarkEvidence:
    return verify_partial_loss_benchmark(
        ProbeOutcomeSummary(
            attempts=128,
            successes=128 - failures,
            failures=failures,
            elapsed_ms=elapsed_ms,
        ),
        QdiscTrafficDelta(
            packets=800,
            bytes=72_000,
            drops=200,
            overlimits=0,
        ),
        configured_loss_percent=20,
        seed=12_648_430,
        runtime_fingerprint=runtime or fingerprint(),
    )


def envelope(
    baseline: PartialLossBenchmarkEvidence | None = None,
    **overrides: object,
) -> dict[str, object]:
    parameters = {
        "max_failure_rate_increase_basis_points": FAILURE_BUDGET,
        "max_elapsed_increase_basis_points": ELAPSED_BUDGET,
        "repository_id": REPOSITORY_ID,
        "workflow_sha": WORKFLOW_SHA,
        "selector_key_id": KEY_ID,
        "issued_at": ISSUED_AT,
        "expires_at": EXPIRES_AT,
        "public_key_der": PUBLIC_KEY,
        "signer": lambda message: SIGNATURE if message else b"",
    }
    parameters.update(overrides)
    return create_baseline_authorization(baseline or benchmark(), **parameters)


def status_envelope(**overrides: object) -> dict[str, object]:
    parameters = {
        "selector_key_id": KEY_ID,
        "selector_public_key_sha256": PUBLIC_KEY_SHA256,
        "state": "active",
        "status_authority_key_id": STATUS_AUTHORITY_KEY_ID,
        "issued_at": ISSUED_AT,
        "expires_at": EXPIRES_AT,
        "authority_public_key_der": STATUS_AUTHORITY_PUBLIC_KEY,
        "signer": lambda message: STATUS_AUTHORITY_SIGNATURE if message else b"",
    }
    parameters.update(overrides)
    return create_selector_key_status(**parameters)


def verify(
    document: object,
    baseline: PartialLossBenchmarkEvidence | None = None,
    **overrides: object,
) -> dict[str, object]:
    parameters = {
        "expected_public_key_sha256": PUBLIC_KEY_SHA256,
        "expected_selector_key_id": KEY_ID,
        "expected_status_authority_public_key_sha256": (
            STATUS_AUTHORITY_PUBLIC_KEY_SHA256
        ),
        "expected_status_authority_key_id": STATUS_AUTHORITY_KEY_ID,
        "repository_id": REPOSITORY_ID,
        "workflow_sha": WORKFLOW_SHA,
        "verification_time": VERIFICATION_TIME,
        "max_failure_rate_increase_basis_points": FAILURE_BUDGET,
        "max_elapsed_increase_basis_points": ELAPSED_BUDGET,
        "signature_verifier": lambda public_key, signature, message: (
            public_key == PUBLIC_KEY and signature == SIGNATURE and bool(message)
        ),
        "status_signature_verifier": lambda public_key, signature, message: (
            public_key == STATUS_AUTHORITY_PUBLIC_KEY
            and signature == STATUS_AUTHORITY_SIGNATURE
            and bool(message)
        ),
    }
    key_status = overrides.pop("key_status_envelope", status_envelope())
    parameters.update(overrides)
    return verify_baseline_authorization(
        document,
        key_status,
        baseline or benchmark(),
        **parameters,
    )


def test_authorizes_exact_baseline_before_releasing_private_comparison() -> None:
    baseline = benchmark()
    candidate = benchmark(failures=5, elapsed_ms=770)
    receipt, comparison = gate_authorized_comparison(
        envelope(baseline),
        status_envelope(),
        baseline,
        candidate,
        expected_public_key_sha256=PUBLIC_KEY_SHA256,
        expected_selector_key_id=KEY_ID,
        expected_status_authority_public_key_sha256=(
            STATUS_AUTHORITY_PUBLIC_KEY_SHA256
        ),
        expected_status_authority_key_id=STATUS_AUTHORITY_KEY_ID,
        repository_id=REPOSITORY_ID,
        workflow_sha=WORKFLOW_SHA,
        verification_time=VERIFICATION_TIME,
        max_failure_rate_increase_basis_points=FAILURE_BUDGET,
        max_elapsed_increase_basis_points=ELAPSED_BUDGET,
        signature_verifier=lambda *_: True,
        status_signature_verifier=lambda *_: True,
    )

    assert comparison.accepted
    assert receipt["schema_version"] == GATE_SCHEMA
    assert receipt["status"] == "pass"
    assert receipt["baseline_benchmark_sha256"] == baseline.digest()
    assert receipt["candidate_benchmark_sha256"] == candidate.digest()
    assert len(receipt["authorization_sha256"]) == 64
    assert len(receipt["selector_key_status_sha256"]) == 64
    assert len(receipt["workflow_binding_sha256"]) == 64
    retained = json.dumps(receipt, sort_keys=True)
    assert REPOSITORY_ID not in retained
    assert WORKFLOW_SHA not in retained
    assert KEY_ID not in retained
    assert STATUS_AUTHORITY_KEY_ID not in retained
    assert base64.b64encode(SIGNATURE).decode("ascii") not in retained
    assert base64.b64encode(PUBLIC_KEY).decode("ascii") not in retained
    assert base64.b64encode(STATUS_AUTHORITY_PUBLIC_KEY).decode("ascii") not in retained


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"expected_public_key_sha256": "f" * 64}, "public-key pin"),
        ({"expected_selector_key_id": "replacement-key"}, "requested gate"),
        ({"repository_id": "42"}, "requested gate"),
        ({"workflow_sha": "b" * 40}, "requested gate"),
        (
            {"max_failure_rate_increase_basis_points": FAILURE_BUDGET + 1},
            "requested gate",
        ),
        (
            {"max_elapsed_increase_basis_points": ELAPSED_BUDGET + 1},
            "requested gate",
        ),
    ],
)
def test_rejects_key_identity_workflow_or_budget_substitution(
    override: dict[str, object], message: str
) -> None:
    with pytest.raises(BaselineAuthorizationRejected, match=message):
        verify(envelope(), **override)


def test_rejects_baseline_substitution_even_when_runtime_policy_match() -> None:
    reviewed = benchmark(failures=4)
    replacement = benchmark(failures=5)
    with pytest.raises(BaselineAuthorizationRejected, match="requested gate"):
        verify(envelope(reviewed), baseline=replacement)


def test_signature_is_checked_before_signed_claims_or_candidate_comparison(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = copy.deepcopy(envelope())
    document["authorization"]["expires_at"] = "2030-01-01T00:00:00Z"

    def comparison_must_not_run(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("comparison ran before signature verification")

    monkeypatch.setattr(
        authorization_module,
        "compare_partial_loss_benchmarks",
        comparison_must_not_run,
    )
    with pytest.raises(BaselineAuthorizationRejected, match="signature is invalid"):
        verify(document, signature_verifier=lambda *_: False)


def test_revoked_selector_key_blocks_comparison_before_semantic_use(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authorization = envelope()
    revoked_status = status_envelope(state="revoked")

    def comparison_must_not_run(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("comparison ran after selector-key revocation")

    monkeypatch.setattr(
        authorization_module,
        "compare_partial_loss_benchmarks",
        comparison_must_not_run,
    )
    with pytest.raises(ValueError, match="selector key is revoked"):
        verify(authorization, key_status_envelope=revoked_status)


@pytest.mark.parametrize(
    ("verification_time", "message"),
    [
        ("2026-11-05T15:59:59Z", "not yet valid"),
        (EXPIRES_AT, "expired"),
        ("2026-11-05T18:00:00Z", "expired"),
    ],
)
def test_rejects_authorization_outside_its_validity_window(
    verification_time: str, message: str
) -> None:
    with pytest.raises(BaselineAuthorizationRejected, match=message):
        verify(envelope(), verification_time=verification_time)


def test_rejects_overlong_authorization_and_noncanonical_envelopes() -> None:
    with pytest.raises(BaselineAuthorizationRejected, match="at most 24 hours"):
        envelope(expires_at="2026-11-06T16:00:01Z")

    document = envelope()
    document["unexpected"] = True
    with pytest.raises(BaselineAuthorizationRejected, match="envelope fields"):
        verify(document)

    document = envelope()
    document["public_key"]["value"] += "\n"
    with pytest.raises(BaselineAuthorizationRejected, match="canonical base64"):
        verify(document)


def test_loader_rejects_duplicate_keys_and_symlinks(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"authorization":{},"authorization":{}}', encoding="utf-8")
    with pytest.raises(BaselineAuthorizationRejected, match="duplicate"):
        load_authorization(duplicate)

    target = tmp_path / "authorization.json"
    target.write_text(json.dumps(envelope()), encoding="utf-8")
    link = tmp_path / "authorization-link.json"
    link.symlink_to(target)
    with pytest.raises(BaselineAuthorizationRejected, match="without following links"):
        load_authorization(link)


@pytest.mark.skipif(shutil.which("openssl") is None, reason="OpenSSL is unavailable")
def test_real_ed25519_signature_and_cli_gate(tmp_path: Path) -> None:
    def key_pair(name: str) -> tuple[bytes, Callable[[bytes], bytes]]:
        private_key = tmp_path / f"{name}-private.pem"
        public_key = tmp_path / f"{name}-public.der"
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "ED25519",
                "-out",
                str(private_key),
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(private_key),
                "-pubout",
                "-outform",
                "DER",
                "-out",
                str(public_key),
            ],
            check=True,
            capture_output=True,
        )

        def sign(message: bytes) -> bytes:
            message_path = tmp_path / f"{name}-message.bin"
            signature_path = tmp_path / f"{name}-signature.bin"
            message_path.write_bytes(message)
            subprocess.run(
                [
                    "openssl",
                    "pkeyutl",
                    "-sign",
                    "-inkey",
                    str(private_key),
                    "-rawin",
                    "-in",
                    str(message_path),
                    "-out",
                    str(signature_path),
                ],
                check=True,
                capture_output=True,
            )
            return signature_path.read_bytes()

        return public_key.read_bytes(), sign

    public_key_der, sign = key_pair("selector")
    authority_public_key_der, sign_status = key_pair("status-authority")

    baseline_evidence = benchmark()
    candidate_evidence = benchmark(failures=5, elapsed_ms=770)
    signed = envelope(
        baseline_evidence,
        public_key_der=public_key_der,
        signer=sign,
    )
    signed_status = status_envelope(
        selector_public_key_sha256=hashlib.sha256(public_key_der).hexdigest(),
        authority_public_key_der=authority_public_key_der,
        signer=sign_status,
    )
    authorization_path = tmp_path / "authorization.json"
    status_path = tmp_path / "selector-key-status.json"
    baseline_path = tmp_path / "baseline.json"
    candidate_path = tmp_path / "candidate.json"
    output_path = tmp_path / "gate.json"
    authorization_path.write_text(json.dumps(signed), encoding="utf-8")
    status_path.write_text(json.dumps(signed_status), encoding="utf-8")
    baseline_path.write_text(json.dumps(baseline_evidence.as_dict()), encoding="utf-8")
    candidate_path.write_text(
        json.dumps(candidate_evidence.as_dict()), encoding="utf-8"
    )

    arguments = [
        str(authorization_path),
        str(status_path),
        str(baseline_path),
        str(candidate_path),
        "--selector-public-key-sha256",
        hashlib.sha256(public_key_der).hexdigest(),
        "--selector-key-id",
        KEY_ID,
        "--status-authority-public-key-sha256",
        hashlib.sha256(authority_public_key_der).hexdigest(),
        "--status-authority-key-id",
        STATUS_AUTHORITY_KEY_ID,
        "--repository-id",
        REPOSITORY_ID,
        "--workflow-sha",
        WORKFLOW_SHA,
        "--verification-time",
        VERIFICATION_TIME,
        "--output",
        str(output_path),
    ]

    assert main(arguments) == 0
    assert json.loads(output_path.read_text(encoding="utf-8"))["status"] == "pass"
    assert os.stat(output_path).st_mode & 0o777 == 0o600

    candidate_path.write_text(
        json.dumps(benchmark(failures=12, elapsed_ms=900).as_dict()),
        encoding="utf-8",
    )
    assert main(arguments) == 3
    assert json.loads(output_path.read_text(encoding="utf-8"))["status"] == "fail"


def test_created_claims_are_strictly_bound_to_reviewed_schema() -> None:
    document = envelope()
    claims = document["authorization"]
    assert claims["schema_version"] == AUTHORIZATION_SCHEMA
    assert claims["baseline_benchmark_sha256"] == benchmark().digest()
    assert claims["max_failure_rate_increase_basis_points"] == FAILURE_BUDGET
    assert claims["max_elapsed_increase_basis_points"] == ELAPSED_BUDGET
