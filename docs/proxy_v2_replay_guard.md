# PROXY v2 replay guard

A valid CRC-32C proves that a PROXY v2 header was not accidentally corrupted; it does not prove
freshness. An attacker or faulty intermediary can copy a previously valid header and present the
same forwarded identity again. `ProxyReplayGuard` closes that gap for listeners whose trusted proxy
emits a high-entropy `PP2_TYPE_UNIQUE_ID` TLV.

```python
from tools.connection_limiter import ConnectionLimiter
from tools.listener_admission import admit_listener_connection
from tools.replay_guard import ProxyReplayGuard, ReplayGuardPolicy

limiter = ConnectionLimiter()
replay_guard = ProxyReplayGuard(
    ReplayGuardPolicy(ttl_seconds=300, max_entries=65_536)
)

result = admit_listener_connection(
    connection,
    immediate_peer="10.10.0.12",
    limiter=limiter,
    proxy_policy=proxy_policy,
    replay_guard=replay_guard,
    read_timeout_seconds=1.0,
)
```

The validated parser hashes the UNIQUE_ID value and never places its raw bytes in admission
evidence. A claim is retained until its monotonic TTL expires. Reusing the same UNIQUE_ID with
different forwarded addresses still produces `proxy_header_replay`, because replay identity is
bound to the identifier rather than the entire header. When the bounded cache is full, admission
fails closed with `replay_guard_capacity_exceeded`; it never evicts a live claim to make room.

Composed evidence schema version 3 binds the replay-policy SHA-256 digest alongside the capacity
and PROXY-policy digests. Snapshots expose fixed-cardinality counters for active claims, accepted
claims, replay rejections, capacity rejections and expirations. They do not expose identifiers as
metric labels.

## Trust boundary and sizing

The trusted proxy must generate unpredictable, unique values. Hashing reduces accidental disclosure
but does not make a low-entropy identifier secret; a small identifier space can be brute-forced.
Choose `max_entries` for the maximum unique connection count expected inside the TTL plus operational
headroom. A full guard rejects new traffic by design, so saturation must be monitored.

This implementation coordinates threads in one process. Multiple workers or hosts need a shared,
atomic claim store with equivalent TTL and capacity semantics. The guard also cannot stop replay
after TTL expiry, prove that the proxy generated an identifier honestly, or replace authenticated
transport between the load balancer and listener.
