from __future__ import annotations

import ipaddress
import socket
import sqlite3
import struct
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

from tools.connection_limiter import ConnectionLimitPolicy, ConnectionLimiter
from tools.listener_admission import (
    admit_listener_connection,
    verify_connection_admission_evidence,
)
from tools.proxy_v2 import (
    FAM_INET_STREAM,
    FIXED_HEADER_BYTES,
    SIGNATURE,
    TLV_CRC32C,
    TLV_UNIQUE_ID,
    ProxyV2Policy,
    crc32c,
)
from tools.replay_guard import ProxyReplayGuard, ReplayGuardPolicy
from tools.sqlite_replay_guard import SQLiteReplayGuard, SQLiteReplayGuardPolicy


def policy() -> ProxyV2Policy:
    return ProxyV2Policy.from_strings(
        trusted_proxy_cidrs=("10.10.0.0/24",),
        destination_cidrs=("10.20.0.0/24",),
        destination_ports=(443,),
    )


def build_header(
    *,
    destination: str = "10.20.0.8",
    unique_id_value: bytes | None = b"request-17",
) -> bytes:
    address_block = (
        ipaddress.ip_address("198.51.100.7").packed
        + ipaddress.ip_address(destination).packed
        + struct.pack("!HH", 53000, 443)
    )
    unique_id = (
        b""
        if unique_id_value is None
        else struct.pack("!BH", TLV_UNIQUE_ID, len(unique_id_value)) + unique_id_value
    )
    crc_offset = FIXED_HEADER_BYTES + len(address_block) + len(unique_id) + 3
    payload = address_block + unique_id + struct.pack("!BH", TLV_CRC32C, 4) + b"\0" * 4
    header = bytearray(
        SIGNATURE
        + b"\x21"
        + bytes([FAM_INET_STREAM])
        + struct.pack("!H", len(payload))
        + payload
    )
    struct.pack_into("!I", header, crc_offset, crc32c(bytes(header)))
    return bytes(header)


def send_header(
    header: bytes, trailing_bytes: bytes = b""
) -> tuple[socket.socket, socket.socket]:
    sender, receiver = socket.socketpair()
    sender.sendall(header + trailing_bytes)
    return sender, receiver


class BufferedSocket:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.timeout: float | None = None
        self.read_calls = 0

    def gettimeout(self) -> float | None:
        return self.timeout

    def settimeout(self, value: float | None) -> None:
        self.timeout = value

    def recv(self, bufsize: int) -> bytes:
        self.read_calls += 1
        chunk, self.data = self.data[:bufsize], self.data[bufsize:]
        return chunk


def test_acceptance_binds_both_policies_and_retains_capacity() -> None:
    limiter = ConnectionLimiter(ConnectionLimitPolicy(max_in_flight=1))
    proxy_policy = policy()
    application_bytes = b"GET /health HTTP/1.1\r\n"
    sender, receiver = send_header(build_header(), application_bytes)
    try:
        result = admit_listener_connection(
            receiver,
            immediate_peer="10.10.0.12",
            limiter=limiter,
            proxy_policy=proxy_policy,
            read_timeout_seconds=0.25,
        )

        assert result.accepted
        assert result.metadata is not None
        assert limiter.snapshot().in_flight == 1
        assert result.evidence.capacity_policy_sha256 == limiter.policy.digest
        assert result.evidence.proxy_policy_sha256 == proxy_policy.digest
        assert result.evidence.proxy_evidence_sha256 is not None
        assert verify_connection_admission_evidence(result.evidence)
        assert receiver.recv(len(application_bytes)) == application_bytes
        assert result.release() is True
        assert result.release() is False
        assert limiter.snapshot().in_flight == 0
    finally:
        sender.close()
        receiver.close()


def test_capacity_rejection_happens_before_socket_read() -> None:
    limiter = ConnectionLimiter(ConnectionLimitPolicy(max_in_flight=1))
    sender, receiver = send_header(build_header())
    try:
        with limiter.acquire():
            result = admit_listener_connection(
                receiver,
                immediate_peer="10.10.0.12",
                limiter=limiter,
                proxy_policy=policy(),
                read_timeout_seconds=0.25,
            )

        assert not result.accepted
        assert result.evidence.reason == "connection_capacity_exceeded"
        assert result.evidence.proxy_evidence_sha256 is None
        assert receiver.recv(1, socket.MSG_PEEK) == build_header()[:1]
        assert limiter.snapshot().rejected_total == 1
        assert verify_connection_admission_evidence(result.evidence)
    finally:
        sender.close()
        receiver.close()


def test_drain_rejection_happens_before_socket_read_and_binds_state() -> None:
    limiter = ConnectionLimiter(ConnectionLimitPolicy(max_in_flight=1))
    connection = BufferedSocket(build_header())
    assert limiter.begin_drain()

    result = admit_listener_connection(
        connection,
        immediate_peer="10.10.0.12",
        limiter=limiter,
        proxy_policy=policy(),
        read_timeout_seconds=0.25,
    )

    assert not result.accepted
    assert result.evidence.reason == "listener_draining"
    assert result.evidence.listener_state == "drained"
    assert result.evidence.schema_version == 3
    assert connection.read_calls == 0
    assert limiter.snapshot().draining_rejected_total == 1
    assert verify_connection_admission_evidence(result.evidence)


def test_parallel_composed_admission_never_reads_rejected_connections() -> None:
    worker_count = 64
    capacity = 8
    limiter = ConnectionLimiter(ConnectionLimitPolicy(max_in_flight=capacity))
    proxy_policy = policy()
    connections = [BufferedSocket(build_header()) for _ in range(worker_count)]
    start = threading.Barrier(worker_count + 1)

    def attempt(connection: BufferedSocket):
        start.wait()
        return admit_listener_connection(
            connection,
            immediate_peer="10.10.0.12",
            limiter=limiter,
            proxy_policy=proxy_policy,
            read_timeout_seconds=0.25,
        )

    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        futures = [pool.submit(attempt, connection) for connection in connections]
        start.wait()
        results = [future.result(timeout=5) for future in futures]

    accepted = [result for result in results if result.accepted]
    rejected = [result for result in results if not result.accepted]
    assert len(accepted) == capacity
    assert len(rejected) == worker_count - capacity
    assert {result.evidence.reason for result in rejected} == {
        "connection_capacity_exceeded"
    }
    assert sum(connection.read_calls > 0 for connection in connections) == capacity
    assert limiter.snapshot().high_watermark == capacity

    for result in accepted:
        assert result.release()
    assert limiter.snapshot().in_flight == 0


@pytest.mark.parametrize(
    ("header", "outcome", "reason"),
    [
        (b"short", "malformed", "truncated_fixed_header"),
        (build_header(destination="10.21.0.8"), "rejected", "destination_cidr_denied"),
    ],
)
def test_proxy_failure_releases_capacity(
    header: bytes, outcome: str, reason: str
) -> None:
    limiter = ConnectionLimiter(ConnectionLimitPolicy(max_in_flight=1))
    sender, receiver = send_header(header)
    sender.shutdown(socket.SHUT_WR)
    try:
        result = admit_listener_connection(
            receiver,
            immediate_peer="10.10.0.12",
            limiter=limiter,
            proxy_policy=policy(),
            read_timeout_seconds=0.25,
        )
        assert result.evidence.outcome == outcome
        assert result.evidence.reason == reason
        assert limiter.snapshot().in_flight == 0
        assert verify_connection_admission_evidence(result.evidence)
    finally:
        sender.close()
        receiver.close()


def test_timeout_releases_capacity_and_normalizes_reason() -> None:
    limiter = ConnectionLimiter(ConnectionLimitPolicy(max_in_flight=1))
    sender, receiver = socket.socketpair()
    try:
        result = admit_listener_connection(
            receiver,
            immediate_peer="10.10.0.12",
            limiter=limiter,
            proxy_policy=policy(),
            read_timeout_seconds=0.01,
        )
        assert result.evidence.outcome == "rejected"
        assert result.evidence.reason == "proxy_header_deadline_exceeded"
        assert limiter.snapshot().in_flight == 0
    finally:
        sender.close()
        receiver.close()


def test_unexpected_reader_error_releases_capacity() -> None:
    class BrokenSocket:
        def gettimeout(self) -> float | None:
            return None

        def settimeout(self, value: float | None) -> None:
            pass

        def recv(self, bufsize: int) -> bytes:
            raise RuntimeError("unexpected reader failure")

    limiter = ConnectionLimiter(ConnectionLimitPolicy(max_in_flight=1))
    with pytest.raises(RuntimeError, match="unexpected reader failure"):
        admit_listener_connection(
            BrokenSocket(),
            immediate_peer="10.10.0.12",
            limiter=limiter,
            proxy_policy=policy(),
            read_timeout_seconds=0.25,
        )
    assert limiter.snapshot().in_flight == 0


def test_evidence_is_privacy_reduced_and_tamper_evident() -> None:
    limiter = ConnectionLimiter(ConnectionLimitPolicy(max_in_flight=1))
    sender, receiver = send_header(build_header())
    try:
        with admit_listener_connection(
            receiver,
            immediate_peer="10.10.0.12",
            limiter=limiter,
            proxy_policy=policy(),
            read_timeout_seconds=0.25,
        ) as result:
            serialized = str(result.evidence.as_dict())
            assert "198.51.100.7" not in serialized
            assert "10.20.0.8" not in serialized
            assert "53000" not in serialized
            assert verify_connection_admission_evidence(result.evidence)
            assert not verify_connection_admission_evidence(
                replace(result.evidence, reason="accepted-but-edited")
            )
            assert not verify_connection_admission_evidence(
                replace(result.evidence, listener_state="draining")
            )
    finally:
        sender.close()
        receiver.close()


def test_replay_guard_rejects_reused_unique_id_and_releases_capacity() -> None:
    limiter = ConnectionLimiter(ConnectionLimitPolicy(max_in_flight=2))
    replay_guard = ProxyReplayGuard(ReplayGuardPolicy(ttl_seconds=30, max_entries=8))
    first_connection = BufferedSocket(build_header(unique_id_value=b"request-17"))
    replayed_connection = BufferedSocket(
        build_header(
            destination="10.20.0.9",
            unique_id_value=b"request-17",
        )
    )

    first = admit_listener_connection(
        first_connection,
        immediate_peer="10.10.0.12",
        limiter=limiter,
        proxy_policy=policy(),
        read_timeout_seconds=0.25,
        replay_guard=replay_guard,
    )
    replayed = admit_listener_connection(
        replayed_connection,
        immediate_peer="10.10.0.12",
        limiter=limiter,
        proxy_policy=policy(),
        read_timeout_seconds=0.25,
        replay_guard=replay_guard,
    )

    assert first.accepted
    assert not replayed.accepted
    assert replayed.evidence.reason == "proxy_header_replay"
    assert replayed.evidence.replay_policy_sha256 == replay_guard.policy.digest
    assert verify_connection_admission_evidence(replayed.evidence)
    assert not verify_connection_admission_evidence(
        replace(replayed.evidence, replay_policy_sha256="0" * 64)
    )
    assert limiter.snapshot().in_flight == 1
    assert first.release()
    assert limiter.snapshot().in_flight == 0


def test_replay_guard_requires_unique_id_without_leaking_header_fields() -> None:
    limiter = ConnectionLimiter(ConnectionLimitPolicy(max_in_flight=1))
    replay_guard = ProxyReplayGuard()
    connection = BufferedSocket(build_header(unique_id_value=None))

    result = admit_listener_connection(
        connection,
        immediate_peer="10.10.0.12",
        limiter=limiter,
        proxy_policy=policy(),
        read_timeout_seconds=0.25,
        replay_guard=replay_guard,
    )

    assert not result.accepted
    assert result.evidence.reason == "proxy_unique_id_required"
    assert result.evidence.proxy_evidence_sha256 is not None
    assert "request-17" not in str(result.evidence.as_dict())
    assert replay_guard.snapshot().claimed_total == 0
    assert limiter.snapshot().in_flight == 0


def test_replay_guard_capacity_rejection_releases_listener_capacity() -> None:
    limiter = ConnectionLimiter(ConnectionLimitPolicy(max_in_flight=1))
    replay_guard = ProxyReplayGuard(ReplayGuardPolicy(ttl_seconds=30, max_entries=1))

    first = admit_listener_connection(
        BufferedSocket(build_header(unique_id_value=b"request-1")),
        immediate_peer="10.10.0.12",
        limiter=limiter,
        proxy_policy=policy(),
        read_timeout_seconds=0.25,
        replay_guard=replay_guard,
    )
    assert first.accepted
    assert first.release()

    second = admit_listener_connection(
        BufferedSocket(build_header(unique_id_value=b"request-2")),
        immediate_peer="10.10.0.12",
        limiter=limiter,
        proxy_policy=policy(),
        read_timeout_seconds=0.25,
        replay_guard=replay_guard,
    )

    assert not second.accepted
    assert second.evidence.reason == "replay_guard_capacity_exceeded"
    assert replay_guard.snapshot().capacity_rejected_total == 1
    assert limiter.snapshot().in_flight == 0


def test_parallel_replay_claim_allows_exactly_one_connection() -> None:
    worker_count = 64
    limiter = ConnectionLimiter(ConnectionLimitPolicy(max_in_flight=worker_count))
    replay_guard = ProxyReplayGuard(
        ReplayGuardPolicy(ttl_seconds=30, max_entries=worker_count)
    )
    proxy_policy = policy()
    connections = [
        BufferedSocket(build_header(unique_id_value=b"same-request"))
        for _ in range(worker_count)
    ]
    start = threading.Barrier(worker_count + 1)

    def attempt(connection: BufferedSocket):
        start.wait()
        return admit_listener_connection(
            connection,
            immediate_peer="10.10.0.12",
            limiter=limiter,
            proxy_policy=proxy_policy,
            read_timeout_seconds=0.25,
            replay_guard=replay_guard,
        )

    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        futures = [pool.submit(attempt, connection) for connection in connections]
        start.wait()
        results = [future.result(timeout=5) for future in futures]

    accepted = [result for result in results if result.accepted]
    rejected = [result for result in results if not result.accepted]
    assert len(accepted) == 1
    assert len(rejected) == worker_count - 1
    assert {result.evidence.reason for result in rejected} == {"proxy_header_replay"}
    snapshot = replay_guard.snapshot()
    assert snapshot.claimed_total == 1
    assert snapshot.replay_rejected_total == worker_count - 1
    assert limiter.snapshot().in_flight == 1
    assert accepted[0].release()
    assert limiter.snapshot().in_flight == 0


def test_sqlite_replay_guard_composes_with_listener_admission(tmp_path) -> None:
    limiter = ConnectionLimiter(ConnectionLimitPolicy(max_in_flight=2))
    replay_guard = SQLiteReplayGuard(
        tmp_path / "replay.db",
        SQLiteReplayGuardPolicy(
            ttl_seconds=30,
            max_entries=8,
            namespace="listener-a",
        ),
    )

    first = admit_listener_connection(
        BufferedSocket(build_header(unique_id_value=b"shared-request")),
        immediate_peer="10.10.0.12",
        limiter=limiter,
        proxy_policy=policy(),
        read_timeout_seconds=0.25,
        replay_guard=replay_guard,
    )
    replayed = admit_listener_connection(
        BufferedSocket(build_header(unique_id_value=b"shared-request")),
        immediate_peer="10.10.0.12",
        limiter=limiter,
        proxy_policy=policy(),
        read_timeout_seconds=0.25,
        replay_guard=replay_guard,
    )

    assert first.accepted
    assert not replayed.accepted
    assert replayed.evidence.reason == "proxy_header_replay"
    assert replayed.evidence.replay_policy_sha256 == replay_guard.policy.digest
    assert verify_connection_admission_evidence(replayed.evidence)
    assert limiter.snapshot().in_flight == 1
    assert first.release()


def test_sqlite_store_failure_rejects_and_releases_capacity(tmp_path) -> None:
    limiter = ConnectionLimiter(ConnectionLimitPolicy(max_in_flight=1))
    database = tmp_path / "locked-replay.db"
    replay_guard = SQLiteReplayGuard(
        database,
        SQLiteReplayGuardPolicy(
            ttl_seconds=30,
            max_entries=8,
            namespace="listener-a",
            busy_timeout_seconds=0.01,
        ),
    )
    blocker = sqlite3.connect(database, isolation_level=None)
    blocker.execute("BEGIN IMMEDIATE")
    try:
        result = admit_listener_connection(
            BufferedSocket(build_header(unique_id_value=b"shared-request")),
            immediate_peer="10.10.0.12",
            limiter=limiter,
            proxy_policy=policy(),
            read_timeout_seconds=0.25,
            replay_guard=replay_guard,
        )
    finally:
        blocker.rollback()
        blocker.close()

    assert not result.accepted
    assert result.evidence.reason == "replay_guard_unavailable"
    assert result.evidence.replay_policy_sha256 == replay_guard.policy.digest
    assert verify_connection_admission_evidence(result.evidence)
    assert limiter.snapshot().in_flight == 0


def test_sqlite_clock_regression_rejects_and_releases_capacity(tmp_path) -> None:
    limiter = ConnectionLimiter(ConnectionLimitPolicy(max_in_flight=1))
    now = [1_000.0]
    replay_guard = SQLiteReplayGuard(
        tmp_path / "clock-replay.db",
        SQLiteReplayGuardPolicy(
            ttl_seconds=30,
            max_entries=8,
            namespace="listener-a",
            max_clock_regression_seconds=0.5,
        ),
        clock=lambda: now[0],
    )
    first = admit_listener_connection(
        BufferedSocket(build_header(unique_id_value=b"request-1")),
        immediate_peer="10.10.0.12",
        limiter=limiter,
        proxy_policy=policy(),
        read_timeout_seconds=0.25,
        replay_guard=replay_guard,
    )
    assert first.accepted
    assert first.release()

    now[0] -= 0.501
    regressed = admit_listener_connection(
        BufferedSocket(build_header(unique_id_value=b"request-2")),
        immediate_peer="10.10.0.12",
        limiter=limiter,
        proxy_policy=policy(),
        read_timeout_seconds=0.25,
        replay_guard=replay_guard,
    )

    assert not regressed.accepted
    assert regressed.evidence.reason == "replay_guard_clock_regression"
    assert regressed.evidence.replay_policy_sha256 == replay_guard.policy.digest
    assert verify_connection_admission_evidence(regressed.evidence)
    assert limiter.snapshot().in_flight == 0
