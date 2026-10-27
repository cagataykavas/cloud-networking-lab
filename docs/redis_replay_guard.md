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
        ambiguous_retry_attempts=1,
        required_replica_acks=1,
        replica_ack_timeout_milliseconds=100,
    ),
)
```

For each claim, the script atomically:

1. binds the namespace to the immutable backend, TTL, capacity and key policy digest;
2. reads Redis server time, avoiding divergent listener-host clocks;
3. removes expired SHA-256 identifiers and accounts for them;
4. binds a cryptographically random operation token to each accepted identifier;
5. treats one repeated operation token as the same committed claim, while rejecting a different
   token for the same identifier as a replay;
6. rejects a full replay window;
7. verifies a persistent policy marker and per-claim token so partial state loss fails closed;
8. inserts the new digest with its expiry and updates bounded-cardinality counters.

The state and sorted-set keys both contain the namespace as a Redis Cluster hash tag, for example
`payments-edge:{public-listener}:state` and `payments-edge:{public-listener}:claims`. They therefore
remain in one cluster slot, which is required for an atomic multi-key script. Namespace and prefix
validation rejects braces and other key-shaping input.

Script, connection, timeout and malformed-response failures become `replay_guard_unavailable`.
A namespace opened with a different policy becomes `replay_guard_policy_mismatch`. Listener
admission also rejects `replay_guard_integrity_error` when either half of an initialized namespace
disappears, or when a live claim loses either its sorted-set member or operation token. These
outcomes release the capacity lease without publishing Redis error text or raw unique IDs.

By default, a claim retries one Redis error with the same random operation token. This closes the
common ambiguous-result window where Redis committed the Lua transaction but the reply was lost:
the second execution returns success without incrementing admission counters a second time. A
different listener invocation creates a different token and remains a replay. Set
`ambiguous_retry_attempts=0` when the additional bounded socket-timeout interval is unacceptable.
Malformed responses are never retried, and exhaustion still fails closed.

Set `required_replica_acks` above zero to make a newly accepted claim wait for that many replicas
before listener admission succeeds. The adapter queues the Lua claim and `WAIT` in a
non-transactional pipeline, which pins both commands to one pooled connection; this matters because
`WAIT` observes the calling connection's last write offset. An acknowledgement shortfall is an
ambiguous durability result, so the one bounded retry reuses the same operation token. If the
shortfall persists, admission fails as `replay_guard_unavailable`. Replays and other negative
decisions remain negative even if their counter updates have not reached the requested replica
count. Leave the default `required_replica_acks=0` when the deployment has no replicas or when the
extra latency is outside the listener budget.

## Deployment boundary

- Use TLS, Redis ACLs and a service identity limited to the guard's exact key prefix and commands.
- Configure bounded connect/socket timeouts on the client; the adapter deliberately does not own
  connection-pool or retry policy.
- Keep one authoritative primary for a namespace. Redis server time removes host-clock drift but
  does not protect against a bad Redis clock.
- `WAIT` reduces the acknowledged replication-loss window; it does not make Redis failover
  linearizable, guarantee replica persistence, or prevent a promoted stale replica. Pair it with a
  tested failover/persistence policy whose loss window matches the threat model, or choose a
  strongly consistent conditional-write store.
- Configure `maxmemory-policy noeviction` for guard storage. A policy marker detects loss of only
  one namespace key, but simultaneous deletion of both keys is indistinguishable from first use.
  State and the marker persist after claims expire so policy identity and counters do not reset.
- Monitor replay, capacity, policy-mismatch and unavailable outcomes. Do not add caller-level claim
  retries: the adapter owns the single token-bound retry and still reports an unresolved result as
  unavailable.

Replica acknowledgement settings change the policy digest to `redis-v3`. Existing `redis-v1` and
`redis-v2` namespaces fail with `replay_guard_policy_mismatch`; deploy a deliberate new namespace
or clear an old namespace only after its replay window has safely elapsed.

The integration suite uses two independent clients, concurrent claimers and Redis server time to
verify exactly-one admission, persisted counters, bounded capacity, expiry, policy-drift rejection
and a lost reply after a committed transaction. It also verifies that a real primary with no
replica fails closed when one acknowledgement is required.

## Reproducible stale-promotion drill

The opt-in Compose profile runs a separate, ephemeral primary/replica pair on loopback ports 16379
and 16380. The drill first proves the replica is synchronized, redirects replication to a closed
loopback port, and then creates two claims on the isolated primary. The ungated claim is admitted;
the replica-gated claim is committed locally but admission is denied because `WAIT` receives no
acknowledgement. The drill shuts down the primary without persistence, promotes the stale replica,
and verifies that the same ungated digest can be admitted again while the replica-gated policy still
denies admission without an acknowledgement.

```bash
docker compose --profile redis-failover up -d --wait redis_fault_primary redis_fault_replica
python -m tools.redis_failover_drill \
  --primary-url redis://127.0.0.1:16379/0 \
  --replica-url redis://127.0.0.1:16380/0 \
  --receipt /tmp/redis-failover-receipt.json
docker compose --profile redis-failover down --volumes
```

The harness refuses non-loopback endpoints, embedded credentials, endpoint reuse and unbounded
timeouts before issuing `REPLICAOF` or `SHUTDOWN`. Its JSON receipt records only policy outcomes and
replication offsets—never claim digests, operation tokens or Redis URLs. CI executes the live drill
and retains the receipt artifact for 14 days; unit tests cover its safety boundary and private atomic
receipt writer.

This deliberately demonstrates a limitation rather than claiming linearizability: `WAIT` protects
admission when the requested replica acknowledgement is unavailable, but it cannot select the
freshest replica or prevent an operator from promoting stale state. Production failover therefore
still requires freshness-aware orchestration or a strongly consistent conditional-write store. The
drill does not model Sentinel/Cluster elections, disk persistence, ACL rotation or network healing.
