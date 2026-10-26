from __future__ import annotations

import hashlib
import heapq
import json
import math
import re
import threading
import time
from dataclasses import asdict, dataclass
from typing import Callable, Protocol


MAX_REPLAY_TTL_SECONDS = 3_600.0
MAX_REPLAY_ENTRIES = 1_000_000
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ReplayPolicy(Protocol):
    @property
    def digest(self) -> str: ...


class ReplayGuard(Protocol):
    policy: ReplayPolicy

    def claim(self, unique_id_sha256: str) -> None: ...


class ReplayGuardUnavailable(RuntimeError):
    """The replay store could not make an atomic admission decision."""

    code = "replay_guard_unavailable"

    def __init__(self, *_args: object) -> None:
        super().__init__(self.code)


class ReplayGuardClockRegression(RuntimeError):
    """The shared store observed an unsafe wall-clock rollback."""

    code = "replay_guard_clock_regression"

    def __init__(self, *_args: object) -> None:
        super().__init__(self.code)


class ReplayGuardPolicyMismatch(RuntimeError):
    """A shared namespace is already bound to a different policy."""

    code = "replay_guard_policy_mismatch"

    def __init__(self, *_args: object) -> None:
        super().__init__(self.code)


class ReplayGuardIntegrityError(RuntimeError):
    """The shared replay namespace lost one side of its atomic state."""

    code = "replay_guard_integrity_error"

    def __init__(self, *_args: object) -> None:
        super().__init__(self.code)


class ProxyHeaderReplay(RuntimeError):
    """The proxy unique identifier is already live in the replay window."""

    code = "proxy_header_replay"

    def __init__(self, *_args: object) -> None:
        super().__init__(self.code)


class ReplayGuardCapacityExceeded(RuntimeError):
    """The bounded replay cache cannot safely admit another identifier."""

    code = "replay_guard_capacity_exceeded"

    def __init__(self, *_args: object) -> None:
        super().__init__(self.code)


@dataclass(frozen=True)
class ReplayGuardPolicy:
    ttl_seconds: float = 300.0
    max_entries: int = 65_536

    def __post_init__(self) -> None:
        if (
            isinstance(self.ttl_seconds, bool)
            or not isinstance(self.ttl_seconds, (int, float))
            or not math.isfinite(self.ttl_seconds)
            or not 0 < self.ttl_seconds <= MAX_REPLAY_TTL_SECONDS
        ):
            raise ValueError(
                f"ttl_seconds must be finite and in (0, {MAX_REPLAY_TTL_SECONDS:g}]"
            )
        if (
            isinstance(self.max_entries, bool)
            or not isinstance(self.max_entries, int)
            or not 1 <= self.max_entries <= MAX_REPLAY_ENTRIES
        ):
            raise ValueError(
                f"max_entries must be an integer in [1, {MAX_REPLAY_ENTRIES}]"
            )

    @property
    def digest(self) -> str:
        document = {
            "max_entries": self.max_entries,
            "ttl_seconds": float(self.ttl_seconds),
        }
        encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode(
            "ascii"
        )
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class ReplayGuardSnapshot:
    active_entries: int
    max_entries: int
    claimed_total: int
    replay_rejected_total: int
    capacity_rejected_total: int
    expired_total: int
    policy_sha256: str
    clock_regression_rejected_total: int = 0

    def as_dict(self) -> dict[str, int | str]:
        return asdict(self)


class ProxyReplayGuard:
    """Thread-safe, bounded TTL claim set for hashed PROXY unique IDs.

    The guard retains only a SHA-256 digest supplied by the validated PROXY v2
    parser. It fails closed at capacity instead of evicting a live claim early.
    """

    def __init__(
        self,
        policy: ReplayGuardPolicy | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.policy = policy or ReplayGuardPolicy()
        self._clock = clock
        self._lock = threading.Lock()
        self._claims: dict[str, float] = {}
        self._expirations: list[tuple[float, str]] = []
        self._claimed_total = 0
        self._replay_rejected_total = 0
        self._capacity_rejected_total = 0
        self._expired_total = 0

    @staticmethod
    def _validate_digest(unique_id_sha256: str) -> None:
        if (
            not isinstance(unique_id_sha256, str)
            or SHA256_RE.fullmatch(unique_id_sha256) is None
        ):
            raise ValueError("unique_id_sha256 must be canonical lowercase SHA-256")

    def _now(self) -> float:
        now = self._clock()
        if not isinstance(now, (int, float)) or not math.isfinite(now):
            raise RuntimeError("replay_guard_clock_invalid")
        return float(now)

    def _expire(self, now: float) -> None:
        while self._expirations and self._expirations[0][0] <= now:
            expiry, digest = heapq.heappop(self._expirations)
            if self._claims.get(digest) == expiry:
                del self._claims[digest]
                self._expired_total += 1

    def claim(self, unique_id_sha256: str) -> None:
        """Claim one identifier for the TTL or reject replay/capacity atomically."""
        self._validate_digest(unique_id_sha256)
        with self._lock:
            now = self._now()
            self._expire(now)
            if unique_id_sha256 in self._claims:
                self._replay_rejected_total += 1
                raise ProxyHeaderReplay
            if len(self._claims) >= self.policy.max_entries:
                self._capacity_rejected_total += 1
                raise ReplayGuardCapacityExceeded
            expiry = now + float(self.policy.ttl_seconds)
            self._claims[unique_id_sha256] = expiry
            heapq.heappush(self._expirations, (expiry, unique_id_sha256))
            self._claimed_total += 1

    def snapshot(self) -> ReplayGuardSnapshot:
        with self._lock:
            self._expire(self._now())
            return ReplayGuardSnapshot(
                active_entries=len(self._claims),
                max_entries=self.policy.max_entries,
                claimed_total=self._claimed_total,
                replay_rejected_total=self._replay_rejected_total,
                capacity_rejected_total=self._capacity_rejected_total,
                expired_total=self._expired_total,
                policy_sha256=self.policy.digest,
            )
