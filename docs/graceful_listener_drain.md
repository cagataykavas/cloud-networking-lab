# Graceful listener drain

Rolling deployments need two distinct shutdown boundaries: stop admitting new
connections, then give already-admitted handlers a bounded grace period. Closing a
listener without that separation can terminate useful work; waiting without a
deadline can stall a deployment indefinitely.

`ConnectionLimiter` implements an irreversible process-local lifecycle:

1. `begin_drain()` atomically moves the listener out of `accepting`.
2. New leases fail immediately with `listener_draining`; composed admission rejects
   them before any bytes are read from the socket.
3. Existing lease owners keep their slots and release normally.
4. `wait_for_drain(timeout_seconds)` uses a monotonic deadline and a condition
   variable, so shutdown does not poll and cannot wait longer than the configured
   grace period.

```python
limiter.begin_drain()
drained = limiter.wait_for_drain(timeout_seconds=30)
if not drained:
    # The process supervisor owns the forced-termination policy.
    raise TimeoutError("listener drain deadline exceeded")
```

The transition is intentionally one-way. A repeated shutdown signal is idempotent,
but a process cannot resume admission with stale lifecycle state. Start a fresh
listener instance for rollback or replacement.

## Evidence and metrics

Admission evidence schema version 2 binds `listener_state` into its SHA-256 digest.
Snapshots expose only fixed-cardinality lifecycle values (`accepting`, `draining`,
`drained`) plus `draining_rejected_total`; client addresses and connection tokens
are never metric labels.

## Scope and limitation

This primitive coordinates threads sharing one `ConnectionLimiter`. A production
server must call `begin_drain()` after its load-balancer readiness endpoint turns
unhealthy and before closing the listening socket. Multi-process or multi-host
draining still requires an orchestrator/load-balancer protocol, and a timed-out
handler needs a separately defined cancellation or forced-termination policy.
