from __future__ import annotations

import hashlib
import json
import math
import threading
import time
from dataclasses import asdict, dataclass
from typing import Self


MAX_CONNECTION_BUDGET = 65_536
MAX_DRAIN_WAIT_SECONDS = 3_600.0


def _validate_drain_timeout(timeout_seconds: float) -> float:
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or not 0 <= timeout_seconds <= MAX_DRAIN_WAIT_SECONDS
    ):
        raise ValueError(
            f"timeout_seconds must be finite and in [0, {MAX_DRAIN_WAIT_SECONDS:g}]"
        )
    return float(timeout_seconds)


class ConnectionCapacityExceeded(RuntimeError):
    """The listener has no immediately available application-handler slot."""

    code = "connection_capacity_exceeded"

    def __init__(self) -> None:
        super().__init__(self.code)


class ListenerDraining(RuntimeError):
    """The listener has stopped accepting new application connections."""

    code = "listener_draining"

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
    draining_rejected_total: int
    high_watermark: int
    policy_sha256: str
    lifecycle_state: str

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
        self._draining_rejected_total = 0
        self._high_watermark = 0
        self._draining = False
        self._drained = threading.Condition(self._lock)

    def acquire(self) -> ConnectionLease:
        """Acquire without blocking or fail closed when capacity is exhausted."""
        with self._drained:
            if self._draining:
                self._rejected_total += 1
                self._draining_rejected_total += 1
                raise ListenerDraining
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
        with self._drained:
            if token not in self._active_tokens:
                raise InvalidConnectionLease
            self._active_tokens.remove(token)
            if self._draining and not self._active_tokens:
                self._drained.notify_all()

    def begin_drain(self) -> bool:
        """Irreversibly reject new leases while existing owners finish.

        Returns ``True`` only for the caller that transitions the listener from
        accepting to draining. Repeated shutdown signals are safe and return
        ``False``.
        """
        with self._drained:
            if self._draining:
                return False
            self._draining = True
            if not self._active_tokens:
                self._drained.notify_all()
            return True

    def wait_for_drain(self, timeout_seconds: float) -> bool:
        """Wait for all pre-drain leases to finish within a monotonic deadline."""
        timeout = _validate_drain_timeout(timeout_seconds)
        deadline = time.monotonic() + timeout
        with self._drained:
            if not self._draining:
                raise RuntimeError("listener_drain_not_started")
            while self._active_tokens:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._drained.wait(timeout=remaining)
            return True

    def drain(self, timeout_seconds: float) -> bool:
        """Begin an idempotent drain and wait for the bounded grace period."""
        _validate_drain_timeout(timeout_seconds)
        self.begin_drain()
        return self.wait_for_drain(timeout_seconds)

    def snapshot(self) -> ConnectionLimitSnapshot:
        with self._drained:
            in_flight = len(self._active_tokens)
            lifecycle_state = (
                "drained"
                if self._draining and in_flight == 0
                else "draining"
                if self._draining
                else "accepting"
            )
            return ConnectionLimitSnapshot(
                max_in_flight=self.policy.max_in_flight,
                in_flight=in_flight,
                available=self.policy.max_in_flight - in_flight,
                admitted_total=self._admitted_total,
                rejected_total=self._rejected_total,
                draining_rejected_total=self._draining_rejected_total,
                high_watermark=self._high_watermark,
                policy_sha256=self.policy.digest,
                lifecycle_state=lifecycle_state,
            )
