from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import asdict, dataclass
from typing import Self


MAX_CONNECTION_BUDGET = 65_536


class ConnectionCapacityExceeded(RuntimeError):
    """The listener has no immediately available application-handler slot."""

    code = "connection_capacity_exceeded"

    def __init__(self) -> None:
        super().__init__(self.code)


class InvalidConnectionLease(RuntimeError):
    """An unknown or already-released lease reached the limiter."""

    code = "invalid_connection_lease"

    def __init__(self) -> None:
        super().__init__(self.code)


@dataclass(frozen=True)
class ConnectionLimitPolicy:
    max_in_flight: int = 256

    def __post_init__(self) -> None:
        if (
            isinstance(self.max_in_flight, bool)
            or not isinstance(self.max_in_flight, int)
            or not 1 <= self.max_in_flight <= MAX_CONNECTION_BUDGET
        ):
            raise ValueError(
                f"max_in_flight must be an integer in [1, {MAX_CONNECTION_BUDGET}]"
            )

    @property
    def digest(self) -> str:
        encoded = json.dumps(
            asdict(self), sort_keys=True, separators=(",", ":")
        ).encode("ascii")
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class ConnectionLimitSnapshot:
    max_in_flight: int
    in_flight: int
    available: int
    admitted_total: int
    rejected_total: int
    high_watermark: int
    policy_sha256: str

    def as_dict(self) -> dict[str, int | str]:
        return asdict(self)


class ConnectionLease:
    """Idempotent context-managed ownership of one listener capacity slot."""

    def __init__(self, limiter: ConnectionLimiter, token: int) -> None:
        self._limiter = limiter
        self._token = token
        self._released = False
        self._release_lock = threading.Lock()

    @property
    def token(self) -> int:
        return self._token

    @property
    def released(self) -> bool:
        with self._release_lock:
            return self._released

    def release(self) -> bool:
        """Release exactly once; return False for a repeated caller cleanup."""
        with self._release_lock:
            if self._released:
                return False
            self._limiter._release(self._token)
            self._released = True
            return True

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.release()


class ConnectionLimiter:
    """Thread-safe, non-queuing listener admission budget.

    A listener should acquire immediately after ``accept`` and retain the lease for
    the complete connection lifecycle. Saturated connections are rejected instead
    of waiting outside the existing PROXY-header deadline.
    """

    def __init__(self, policy: ConnectionLimitPolicy | None = None) -> None:
        self.policy = policy or ConnectionLimitPolicy()
        self._lock = threading.Lock()
        self._next_token = 0
        self._active_tokens: set[int] = set()
        self._admitted_total = 0
        self._rejected_total = 0
        self._high_watermark = 0

    def acquire(self) -> ConnectionLease:
        """Acquire without blocking or fail closed when capacity is exhausted."""
        with self._lock:
            if len(self._active_tokens) >= self.policy.max_in_flight:
                self._rejected_total += 1
                raise ConnectionCapacityExceeded
            self._next_token += 1
            token = self._next_token
            self._active_tokens.add(token)
            self._admitted_total += 1
            self._high_watermark = max(self._high_watermark, len(self._active_tokens))
        return ConnectionLease(self, token)

    def _release(self, token: int) -> None:
        with self._lock:
            if token not in self._active_tokens:
                raise InvalidConnectionLease
            self._active_tokens.remove(token)

    def snapshot(self) -> ConnectionLimitSnapshot:
        with self._lock:
            in_flight = len(self._active_tokens)
            return ConnectionLimitSnapshot(
                max_in_flight=self.policy.max_in_flight,
                in_flight=in_flight,
                available=self.policy.max_in_flight - in_flight,
                admitted_total=self._admitted_total,
                rejected_total=self._rejected_total,
                high_watermark=self._high_watermark,
                policy_sha256=self.policy.digest,
            )
