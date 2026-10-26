# Fleet-wide Redis replay guard

`RedisReplayGuard` extends validated PROXY v2 unique-ID replay admission across listener hosts that
share one Redis primary. It keeps the same fail-closed listener interface as the in-memory and
SQLite adapters while moving the entire decision into one Lua execution.

```python
import redis

from tools.redis_replay_guard import RedisReplayGuard, RedisReplayGuardPolicy

client = redis.Redis.from_url(
    "rediss://replay.internal:6379/0",
    socket_connect_timeout=0.25,
    socket_timeout=0.25,
    health_check_interval=15,
)
replay_guard = RedisReplayGuard(
    client,
    RedisReplayGuardPolicy(
        ttl_milliseconds=300_000,
        max_entries=65_536,
        namespace="public-listener",
        key_prefix="payments-edge",
    ),
)
```

For each claim, the script atomically:

1. binds the namespace to the immutable backend, TTL, capacity and key policy digest;
2. reads Redis server time, avoiding divergent listener-host clocks;
3. removes expired SHA-256 identifiers and accounts for them;
4. rejects a live duplicate or a full replay window;
5. verifies a persistent policy marker so partial state/claim-key loss fails closed;
6. inserts the new digest with its expiry and updates bounded-cardinality counters.

The state and sorted-set keys both contain the namespace as a Redis Cluster hash tag, for example
`payments-edge:{public-listener}:state` and `payments-edge:{public-listener}:claims`. They therefore
remain in one cluster slot, which is required for an atomic multi-key script. Namespace and prefix
validation rejects braces and other key-shaping input.

Script, connection, timeout and malformed-response failures become `replay_guard_unavailable`.
A namespace opened with a different policy becomes `replay_guard_policy_mismatch`. Listener
admission also rejects `replay_guard_integrity_error` when either half of an initialized namespace
disappears. These outcomes release the capacity lease without publishing Redis error text or raw
unique IDs.

## Deployment boundary

- Use TLS, Redis ACLs and a service identity limited to the guard's exact key prefix and commands.
- Configure bounded connect/socket timeouts on the client; the adapter deliberately does not own
  connection-pool or retry policy.
- Keep one authoritative primary for a namespace. Redis server time removes host-clock drift but
  does not protect against a bad Redis clock.
- Treat asynchronous failover as a replay-risk decision: an acknowledged claim can be lost before
  replication. Use a persistence/replication policy whose loss window matches the threat model, or
  choose a strongly consistent conditional-write store.
- Configure `maxmemory-policy noeviction` for guard storage. A policy marker detects loss of only
  one namespace key, but simultaneous deletion of both keys is indistinguishable from first use.
  State and the marker persist after claims expire so policy identity and counters do not reset.
- Monitor replay, capacity, policy-mismatch and unavailable outcomes. Avoid automatic retries after
  an unknown script result because the claim may already have committed.

The integration suite uses two independent clients, concurrent claimers and Redis server time to
verify exactly-one admission, persisted counters, bounded capacity, expiry and policy-drift
rejection. It does not simulate primary failover, replication lag, ACL changes or network
partitions.
