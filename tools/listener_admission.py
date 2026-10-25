from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict, dataclass
from typing import Self

from tools.connection_limiter import (
    ConnectionCapacityExceeded,
    ConnectionLease,
    ConnectionLimiter,
    ListenerDraining,
)
from tools.proxy_v2 import (
    HeaderReadDeadlineExceeded,
    MalformedHeader,
    PolicyRejected,
    ProxyMetadata,
    ProxyV2Policy,
    SocketReader,
    admit_proxy_v2,
    read_proxy_v2_socket,
)
from tools.replay_guard import (
    ProxyHeaderReplay,
    ReplayGuard,
    ReplayGuardCapacityExceeded,
    ReplayGuardClockRegression,
    ReplayGuardUnavailable,
)


@dataclass(frozen=True)
class ConnectionAdmissionEvidence:
    schema_version: int
    outcome: str
    reason: str
    capacity_policy_sha256: str
    proxy_policy_sha256: str
    proxy_evidence_sha256: str | None
    replay_policy_sha256: str | None
    header_bytes: int | None
    address_family: str | None
    listener_state: str
    evidence_sha256: str

    def as_dict(self) -> dict[str, int | str | None]:
        return asdict(self)


@dataclass
class ListenerAdmissionResult:
    """Admission decision and ownership of an accepted connection slot."""

    evidence: ConnectionAdmissionEvidence
    metadata: ProxyMetadata | None
    _lease: ConnectionLease | None = None

    @property
    def accepted(self) -> bool:
        return self.evidence.outcome == "accepted"

    def release(self) -> bool:
        if self._lease is None:
            return False
        released = self._lease.release()
        if released:
            self._lease = None
        return released

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.release()


def _sha256_json(document: object) -> str:
    encoded = json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _evidence(
    *,
    outcome: str,
    reason: str,
    limiter: ConnectionLimiter,
    proxy_policy: ProxyV2Policy,
    proxy_evidence_sha256: str | None = None,
    header_bytes: int | None = None,
    address_family: str | None = None,
    replay_guard: ReplayGuard | None = None,
) -> ConnectionAdmissionEvidence:
    listener_state = limiter.snapshot().lifecycle_state
    document = {
        "address_family": address_family,
        "capacity_policy_sha256": limiter.policy.digest,
        "header_bytes": header_bytes,
        "listener_state": listener_state,
        "outcome": outcome,
        "proxy_evidence_sha256": proxy_evidence_sha256,
        "proxy_policy_sha256": proxy_policy.digest,
        "replay_policy_sha256": (
            replay_guard.policy.digest if replay_guard is not None else None
        ),
        "reason": reason,
        "schema_version": 3,
    }
    return ConnectionAdmissionEvidence(
        **document,
        evidence_sha256=_sha256_json(document),
    )


def verify_connection_admission_evidence(
    evidence: ConnectionAdmissionEvidence,
) -> bool:
    """Verify content integrity; this SHA-256 digest is not authentication."""
    document = evidence.as_dict()
    claimed = document.pop("evidence_sha256")
    if evidence.schema_version != 3 or not isinstance(claimed, str):
        return False
    return hmac.compare_digest(claimed, _sha256_json(document))


def admit_listener_connection(
    connection: SocketReader,
    *,
    immediate_peer: str,
    limiter: ConnectionLimiter,
    proxy_policy: ProxyV2Policy,
    read_timeout_seconds: float,
    replay_guard: ReplayGuard | None = None,
) -> ListenerAdmissionResult:
    """Acquire capacity and admit one PROXY v2 connection without queuing.

    Capacity rejection occurs before reading from the socket. When supplied, the
    replay guard claims the validated, hashed PROXY unique ID before acceptance.
    Every failure after acquisition releases the lease; a successful caller owns
    it until ``ListenerAdmissionResult.release`` or context-manager exit.
    """
    try:
        lease = limiter.acquire()
    except ListenerDraining:
        return ListenerAdmissionResult(
            evidence=_evidence(
                outcome="rejected",
                reason=ListenerDraining.code,
                limiter=limiter,
                proxy_policy=proxy_policy,
                replay_guard=replay_guard,
            ),
            metadata=None,
        )
    except ConnectionCapacityExceeded:
        return ListenerAdmissionResult(
            evidence=_evidence(
                outcome="rejected",
                reason=ConnectionCapacityExceeded.code,
                limiter=limiter,
                proxy_policy=proxy_policy,
                replay_guard=replay_guard,
            ),
            metadata=None,
        )

    try:
        try:
            header = read_proxy_v2_socket(
                connection,
                max_header_bytes=proxy_policy.max_header_bytes,
                read_timeout_seconds=read_timeout_seconds,
            )
        except HeaderReadDeadlineExceeded:
            lease.release()
            return ListenerAdmissionResult(
                evidence=_evidence(
                    outcome="rejected",
                    reason="proxy_header_deadline_exceeded",
                    limiter=limiter,
                    proxy_policy=proxy_policy,
                    replay_guard=replay_guard,
                ),
                metadata=None,
            )
        except MalformedHeader as exc:
            lease.release()
            return ListenerAdmissionResult(
                evidence=_evidence(
                    outcome="malformed",
                    reason=str(exc),
                    limiter=limiter,
                    proxy_policy=proxy_policy,
                    replay_guard=replay_guard,
                ),
                metadata=None,
            )
        except PolicyRejected as exc:
            lease.release()
            return ListenerAdmissionResult(
                evidence=_evidence(
                    outcome="rejected",
                    reason=str(exc),
                    limiter=limiter,
                    proxy_policy=proxy_policy,
                    replay_guard=replay_guard,
                ),
                metadata=None,
            )

        proxy_result = admit_proxy_v2(
            header,
            immediate_peer=immediate_peer,
            policy=proxy_policy,
        )
        if not proxy_result.accepted:
            lease.release()
            return ListenerAdmissionResult(
                evidence=_evidence(
                    outcome=proxy_result.evidence.outcome,
                    reason=proxy_result.evidence.reason,
                    limiter=limiter,
                    proxy_policy=proxy_policy,
                    proxy_evidence_sha256=proxy_result.evidence.evidence_sha256,
                    header_bytes=proxy_result.evidence.header_bytes,
                    address_family=proxy_result.evidence.address_family,
                    replay_guard=replay_guard,
                ),
                metadata=None,
            )
        if replay_guard is not None:
            unique_id_sha256 = proxy_result.evidence.unique_id_sha256
            if unique_id_sha256 is None:
                lease.release()
                return ListenerAdmissionResult(
                    evidence=_evidence(
                        outcome="rejected",
                        reason="proxy_unique_id_required",
                        limiter=limiter,
                        proxy_policy=proxy_policy,
                        proxy_evidence_sha256=proxy_result.evidence.evidence_sha256,
                        header_bytes=proxy_result.evidence.header_bytes,
                        address_family=proxy_result.evidence.address_family,
                        replay_guard=replay_guard,
                    ),
                    metadata=None,
                )
            try:
                replay_guard.claim(unique_id_sha256)
            except (
                ProxyHeaderReplay,
                ReplayGuardCapacityExceeded,
                ReplayGuardClockRegression,
                ReplayGuardUnavailable,
            ) as exc:
                lease.release()
                return ListenerAdmissionResult(
                    evidence=_evidence(
                        outcome="rejected",
                        reason=exc.code,
                        limiter=limiter,
                        proxy_policy=proxy_policy,
                        proxy_evidence_sha256=proxy_result.evidence.evidence_sha256,
                        header_bytes=proxy_result.evidence.header_bytes,
                        address_family=proxy_result.evidence.address_family,
                        replay_guard=replay_guard,
                    ),
                    metadata=None,
                )
        evidence = _evidence(
            outcome="accepted",
            reason="accepted",
            limiter=limiter,
            proxy_policy=proxy_policy,
            proxy_evidence_sha256=proxy_result.evidence.evidence_sha256,
            header_bytes=proxy_result.evidence.header_bytes,
            address_family=proxy_result.evidence.address_family,
            replay_guard=replay_guard,
        )
        return ListenerAdmissionResult(
            evidence=evidence,
            metadata=proxy_result.metadata,
            _lease=lease,
        )
    except BaseException:
        lease.release()
        raise
