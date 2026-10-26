# Shared SQLite replay guard

`ProxyReplayGuard` protects threads inside one listener process. `SQLiteReplayGuard` preserves the
same bounded TTL and fail-closed capacity semantics across independent worker processes on one host.
It uses only Python's standard library and stores SHA-256 identifiers rather than raw PROXY values.

```python
from tools.sqlite_replay_guard import SQLiteReplayGuard, SQLiteReplayGuardPolicy

replay_guard = SQLiteReplayGuard(
    "/run/my-service/proxy-replay.db",
    SQLiteReplayGuardPolicy(
        ttl_seconds=300,
        max_entries=65_536,
        namespace="public-listener",
        busy_timeout_seconds=1,
        max_clock_regression_seconds=1,
    ),
)
```

Each claim opens an independent connection and executes under `BEGIN IMMEDIATE`. Expiry, duplicate
detection, capacity enforcement, claim insertion and counters therefore commit atomically. The
database uses WAL journaling and full synchronous writes. A lock timeout or SQLite error becomes
`replay_guard_unavailable`; listener admission catches it and rejects the connection instead of
bypassing freshness checks.

The store also persists a per-namespace wall-clock watermark. A small rollback within
`max_clock_regression_seconds` is clamped to the last observed value, so it cannot extend a new
claim's lifetime. A larger rollback rejects admission with `replay_guard_clock_regression` and
increments `clock_regression_rejected_total` in the same transaction. The tolerance is part of the
immutable policy digest. This makes clock rollback visible and fail-closed across every worker that
shares the database; it is not a replacement for host time synchronization.

Namespaces allow multiple listeners to share one database without sharing identities. The first
process binds a namespace to the full policy digest, including the SQLite backend, TTL, capacity and
busy timeout. A later process with different settings fails closed rather than silently weakening an
existing replay window. Policy changes require a deliberate new namespace or store migration.

## Deployment boundary

- Put the database in a service-owned directory with restrictive filesystem permissions.
- All worker processes must use the same database path, namespace and policy.
- Monitor replay, capacity and unavailable rejections; a full or locked store rejects new traffic.
- Alert on `clock_regression_rejected_total`; resume admission only after the host clock reaches the
  stored watermark or an operator deliberately migrates to a new namespace.
- Do not place the WAL database on NFS or assume it coordinates separate hosts.
- Back up only if replay counters are operational records; stale claims naturally expire.

This adapter closes the multi-process gap on one host. Use `RedisReplayGuard` when separate hosts
must share one atomic claim decision; its different replication and failover boundary is documented
in `docs/redis_replay_guard.md`. The SQLite watermark catches backward jumps, but large forward
jumps can still expire claims early, so production hosts need time synchronization.
