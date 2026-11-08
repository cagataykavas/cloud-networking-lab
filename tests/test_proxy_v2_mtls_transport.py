from __future__ import annotations

import hashlib
import os
import socket
import ssl
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from tools.proxy_v2_loopback import build_loopback_receipt
from tools.proxy_v2_mtls_transport import (
    MAX_FRAME_BYTES,
    AppendRejected,
    MTLSTransportError,
    _Deadline,
    _FRAME_HEADER,
    _parse_response,
    _receive_frame,
    _verify_checkpoint_binding,
    build_client_context,
    build_server_context,
    collect_one_append,
    deliver_append_request,
)
from tools.proxy_v2_receipt_ledger import (
    GENESIS_HEAD,
    append_receipt,
    build_append_request,
    verify_ledger,
)

REQUEST_KEY = bytes(range(32))
CHECKPOINT_KEY = bytes(reversed(range(32)))
PAYLOAD = b"proxy-v2-application-frame\n"


def _run_openssl(directory: Path, *arguments: str) -> None:
    subprocess.run(
        ["openssl", *arguments],
        cwd=directory,
        check=True,
        capture_output=True,
        text=True,
    )


def _fingerprint(path: Path) -> str:
    der = ssl.PEM_cert_to_DER_cert(path.read_text(encoding="ascii"))
    return hashlib.sha256(der).hexdigest()


@pytest.fixture(scope="module")
def tls_material(tmp_path_factory: pytest.TempPathFactory) -> dict[str, object]:
    directory = tmp_path_factory.mktemp("mtls")
    (directory / "server.ext").write_text(
        "basicConstraints=CA:FALSE\n"
        "subjectAltName=DNS:localhost\n"
        "extendedKeyUsage=serverAuth\n",
        encoding="ascii",
    )
    (directory / "client.ext").write_text(
        "basicConstraints=CA:FALSE\nextendedKeyUsage=clientAuth\n",
        encoding="ascii",
    )
    _run_openssl(
        directory,
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-sha256",
        "-nodes",
        "-days",
        "1",
        "-subj",
        "/CN=receipt-test-ca",
        "-keyout",
        "ca.key",
        "-out",
        "ca.pem",
    )
    for identity in ("server", "client"):
        _run_openssl(
            directory,
            "req",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-nodes",
            "-subj",
            f"/CN={identity if identity == 'client' else 'localhost'}",
            "-keyout",
            f"{identity}.key",
            "-out",
            f"{identity}.csr",
        )
        command = [
            "x509",
            "-req",
            "-sha256",
            "-days",
            "1",
            "-in",
            f"{identity}.csr",
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-out",
            f"{identity}.pem",
            "-extfile",
            f"{identity}.ext",
        ]
        command.extend(
            ["-CAcreateserial"] if identity == "server" else ["-CAserial", "ca.srl"]
        )
        _run_openssl(directory, *command)

    for key_path in directory.glob("*.key"):
        key_path.chmod(0o600)

    ca_file = directory / "ca.pem"
    server_certificate = directory / "server.pem"
    client_certificate = directory / "client.pem"
    return {
        "client_context": build_client_context(
            ca_file=ca_file,
            certificate_file=client_certificate,
            private_key_file=directory / "client.key",
        ),
        "server_context": build_server_context(
            ca_file=ca_file,
            certificate_file=server_certificate,
            private_key_file=directory / "server.key",
        ),
        "server_pin": _fingerprint(server_certificate),
        "client_pin": _fingerprint(client_certificate),
        "directory": directory,
    }


def _receipt(payload: bytes = PAYLOAD):
    return build_loopback_receipt(
        application_payload=payload,
        capacity_policy_sha256="1" * 64,
        proxy_policy_sha256="2" * 64,
        proxy_admission_evidence_sha256="3" * 64,
        connection_admission_evidence_sha256="4" * 64,
    )


def _request(*, expected_head: str = GENESIS_HEAD, nonce: str = "run-1"):
    return build_append_request(
        _receipt(),
        expected_head=expected_head,
        nonce=nonce,
        request_key=REQUEST_KEY,
        expected_payload=PAYLOAD,
    )


def _listener() -> tuple[socket.socket, int]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    return listener, listener.getsockname()[1]


def _collect(
    listener: socket.socket,
    *,
    tls_material: dict[str, object],
    ledger: Path,
    client_pins: set[str] | None = None,
):
    return collect_one_append(
        listener,
        context=tls_material["server_context"],
        trusted_client_certificate_sha256=client_pins or {tls_material["client_pin"]},
        ledger_path=ledger,
        request_key=REQUEST_KEY,
        checkpoint_key=CHECKPOINT_KEY,
        expected_payload=PAYLOAD,
        timeout_seconds=3.0,
    )


def _deliver(
    port: int,
    *,
    tls_material: dict[str, object],
    request=None,
    server_hostname: str = "localhost",
    server_pins: set[str] | None = None,
):
    return deliver_append_request(
        "127.0.0.1",
        port,
        server_hostname=server_hostname,
        context=tls_material["client_context"],
        trusted_server_certificate_sha256=server_pins or {tls_material["server_pin"]},
        receipt=_receipt(),
        request=request or _request(),
        timeout_seconds=3.0,
    )


def test_real_mtls_loopback_appends_and_returns_checkpoint(
    tmp_path: Path, tls_material: dict[str, object]
) -> None:
    ledger = tmp_path / "receipts.jsonl"
    listener, port = _listener()
    with listener, ThreadPoolExecutor(max_workers=1) as executor:
        collected = executor.submit(
            _collect, listener, tls_material=tls_material, ledger=ledger
        )
        checkpoint = _deliver(port, tls_material=tls_material)
        result = collected.result(timeout=5)

    assert result.accepted is True
    assert result.checkpoint == checkpoint
    assert result.local_rejection_code is None
    verify_ledger(
        ledger,
        checkpoint,
        request_key=REQUEST_KEY,
        checkpoint_key=CHECKPOINT_KEY,
        expected_head=checkpoint.ledger_head_sha256,
    )
    assert ledger.stat().st_mode & 0o777 == 0o600


def test_application_rejection_is_generic_on_wire_and_detailed_locally(
    tmp_path: Path, tls_material: dict[str, object]
) -> None:
    ledger = tmp_path / "receipts.jsonl"
    first = append_receipt(
        ledger,
        _receipt(),
        _request(),
        request_key=REQUEST_KEY,
        checkpoint_key=CHECKPOINT_KEY,
        expected_payload=PAYLOAD,
    )
    original = ledger.read_bytes()
    stale_request = _request(expected_head=GENESIS_HEAD, nonce="run-2")
    listener, port = _listener()
    with listener, ThreadPoolExecutor(max_workers=1) as executor:
        collected = executor.submit(
            _collect, listener, tls_material=tls_material, ledger=ledger
        )
        with pytest.raises(AppendRejected, match="^append_rejected$"):
            _deliver(port, tls_material=tls_material, request=stale_request)
        result = collected.result(timeout=5)

    assert result.accepted is False
    assert result.checkpoint is None
    assert result.local_rejection_code == "stale_ledger_head"
    assert ledger.read_bytes() == original
    verify_ledger(
        ledger,
        first,
        request_key=REQUEST_KEY,
        checkpoint_key=CHECKPOINT_KEY,
    )


def test_server_certificate_pin_mismatch_sends_no_request(
    tmp_path: Path, tls_material: dict[str, object]
) -> None:
    ledger = tmp_path / "receipts.jsonl"
    listener, port = _listener()
    with listener, ThreadPoolExecutor(max_workers=1) as executor:
        collected = executor.submit(
            _collect, listener, tls_material=tls_material, ledger=ledger
        )
        with pytest.raises(MTLSTransportError, match="server_certificate_pin_mismatch"):
            _deliver(
                port,
                tls_material=tls_material,
                server_pins={"f" * 64},
            )
        with pytest.raises(MTLSTransportError):
            collected.result(timeout=5)

    assert not ledger.exists()


def test_client_certificate_pin_mismatch_rejects_before_request_read(
    tmp_path: Path, tls_material: dict[str, object]
) -> None:
    ledger = tmp_path / "receipts.jsonl"
    listener, port = _listener()
    with listener, ThreadPoolExecutor(max_workers=1) as executor:
        collected = executor.submit(
            _collect,
            listener,
            tls_material=tls_material,
            ledger=ledger,
            client_pins={"e" * 64},
        )
        with pytest.raises(MTLSTransportError):
            _deliver(port, tls_material=tls_material)
        with pytest.raises(MTLSTransportError, match="client_certificate_pin_mismatch"):
            collected.result(timeout=5)

    assert not ledger.exists()


def test_hostname_mismatch_fails_ca_validation_before_append(
    tmp_path: Path, tls_material: dict[str, object]
) -> None:
    ledger = tmp_path / "receipts.jsonl"
    listener, port = _listener()
    with listener, ThreadPoolExecutor(max_workers=1) as executor:
        collected = executor.submit(
            _collect, listener, tls_material=tls_material, ledger=ledger
        )
        with pytest.raises(MTLSTransportError, match="tls_connection_failed"):
            _deliver(
                port,
                tls_material=tls_material,
                server_hostname="collector.invalid",
            )
        with pytest.raises(MTLSTransportError, match="tls_connection_failed"):
            collected.result(timeout=5)

    assert not ledger.exists()


def test_contexts_require_tls13_and_private_keys(
    tls_material: dict[str, object], tmp_path: Path
) -> None:
    client_context = tls_material["client_context"]
    server_context = tls_material["server_context"]
    assert client_context.minimum_version is ssl.TLSVersion.TLSv1_3
    assert client_context.check_hostname is True
    assert client_context.verify_mode is ssl.CERT_REQUIRED
    assert server_context.minimum_version is ssl.TLSVersion.TLSv1_3
    assert server_context.verify_mode is ssl.CERT_REQUIRED

    directory = tls_material["directory"]
    open_key = tmp_path / "client.key"
    open_key.write_bytes((directory / "client.key").read_bytes())
    os.chmod(open_key, 0o640)
    with pytest.raises(ValueError, match="permissions_too_open"):
        build_client_context(
            ca_file=directory / "ca.pem",
            certificate_file=directory / "client.pem",
            private_key_file=open_key,
        )

    insecure_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    insecure_context.check_hostname = False
    insecure_context.verify_mode = ssl.CERT_NONE
    with pytest.raises(ValueError, match="tls_context_policy_invalid"):
        deliver_append_request(
            "127.0.0.1",
            443,
            server_hostname="localhost",
            context=insecure_context,
            trusted_server_certificate_sha256={tls_material["server_pin"]},
            receipt=_receipt(),
            request=_request(),
        )


def test_frame_and_response_parsers_fail_closed() -> None:
    left, right = socket.socketpair()
    with left, right:
        right.sendall(_FRAME_HEADER.pack(MAX_FRAME_BYTES + 1))
        with pytest.raises(MTLSTransportError, match="frame_size_invalid"):
            _receive_frame(left, _Deadline(1.0))

    duplicate = (
        b'{"code":"append_rejected","code":"detail",'
        b'"schema_version":1,"status":"rejected"}'
    )
    with pytest.raises(MTLSTransportError, match="duplicate_field"):
        _parse_response(duplicate)

    boolean_version = (
        b'{"code":"append_rejected","schema_version":true,"status":"rejected"}'
    )
    with pytest.raises(MTLSTransportError, match="response_fields_invalid"):
        _parse_response(boolean_version)


def test_checkpoint_response_must_bind_the_exact_request(tmp_path: Path) -> None:
    ledger = tmp_path / "receipts.jsonl"
    checkpoint = append_receipt(
        ledger,
        _receipt(),
        _request(),
        request_key=REQUEST_KEY,
        checkpoint_key=CHECKPOINT_KEY,
        expected_payload=PAYLOAD,
    )
    _verify_checkpoint_binding(checkpoint, _receipt(), _request())

    substituted = _request(nonce="other-run")
    with pytest.raises(MTLSTransportError, match="checkpoint_mismatch"):
        _verify_checkpoint_binding(checkpoint, _receipt(), substituted)
