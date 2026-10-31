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

## Promotion freshness proof

`WAIT` cannot decide whether a failover candidate contains the minimum state required by an
external promotion authority. Gate every replay-serving entry point with
`execute_after_promotion_proof` before invoking `RedisReplayGuard.claim` on a promoted node:

```python
from tools.redis_promotion_proof import (
    RedisPromotionPolicy,
    RedisReplicationSnapshot,
    execute_after_promotion_proof,
    load_promotion_proof_json,
)

snapshot = RedisReplicationSnapshot.from_info(redis_client.info("replication"))
proof = load_promotion_proof_json(received_text)
policy = RedisPromotionPolicy(
    cluster_id="edge-replay",
    candidate_id="redis-b",
    minimum_authority_epoch=42,
    keyring={"rotation-7": promotion_hmac_key},
)
authorization, result = execute_after_promotion_proof(
    proof,
    policy,
    snapshot,
    now=trusted_unix_time,
    operation=lambda: replay_guard.claim(unique_id_sha256),
)
```

The HMAC-SHA256 proof has a strict schema and binds the cluster, candidate, authority epoch,
authority-required minimum offset, candidate-observed offset, SHA-256 commitment to the replication
ID, issue/expiry times and key ID. Verification uses constant-time signature comparison and then
fails closed on an unknown key, scope mismatch, stale epoch, invalid lifetime, future/expired proof,
candidate below the signed offset floor, non-promoted role, replication-ID change or offset
regression. The callback is invoked only after all checks pass.

Keep `minimum_authority_epoch` in a durable, rollback-protected control plane and issue proofs only
after the failover controller has selected a candidate and established the required offset. Load the
keyring from a secret manager, overlap keys during rotation and remove retired key IDs after the
maximum proof lifetime. Proof digests and replication-ID commitments are suitable for low-cardinality
evidence; raw replication IDs and HMAC material are not.

This is authenticated orchestration evidence, not consensus, remote attestation or a distributed
lease. A compromised shared HMAC key can authorize a stale candidate, an incorrect minimum offset
remains incorrect after signing, and any replay-serving path that bypasses the wrapper remains
unsafe. The verifier deliberately does not persist epochs or discover failover topology.

### Durable authority ledger

`SQLitePromotionAuthority` persists the election decision that feeds the proof signer. Each row
binds the cluster, monotonic authority epoch, selected candidate, minimum replication offset,
replication-ID commitment and observation time into a SHA-256 chain. Revisions are append-only,
written under `BEGIN IMMEDIATE`, revalidated on every operation and protected by no-update/no-delete
triggers. The database is created with mode `0600`; secrets and raw replication IDs are never stored.
Source-aware version-2 rows also bind a SHA-256 commitment to the validated election observation.

```python
from tools.redis_promotion_authority import SQLitePromotionAuthority

authority = SQLitePromotionAuthority("/var/lib/replay/authority.db", "edge-replay")
previous = authority.snapshot()
state = authority.advance(
    authority_epoch=43,
    candidate_id="redis-b",
    minimum_replication_offset=required_offset,
    snapshot=promoted_snapshot,
    observed_at=trusted_unix_time,
    expected_state_sha256=previous.state_sha256 if previous else None,
)
proof = authority.issue_proof(
    expected_state_sha256=state.state_sha256,
    candidate_id="redis-b",
    snapshot=current_snapshot,
    issued_at=trusted_unix_time,
    expires_at=trusted_unix_time + 30,
    key_id="rotation-8",
    secret=promotion_hmac_key,
)
```

Persist the returned `state_sha256` in the failover controller's own rollback-protected checkpoint
and require it on the next update and every proof issuance. This compare-and-swap token rejects stale
concurrent writers and detects a database restored behind that external checkpoint. Exact retries are
idempotent; reused epochs, decreasing offset floors, regressing observation times, candidate/role/
replication-ID drift and SQLite lock failures all fail closed.

Existing version-1 databases are migrated in place by adding nullable schema and source columns in
the same initialization transaction. Their historical digests retain the version-1 payload shape;
the first source-aware append starts version 2 and chains to the existing head. Once a chain contains
a version-2 row, later revisions cannot silently omit the source commitment.

The ledger is deliberately a single-host coordination primitive, not Sentinel/Cluster discovery,
leader election, distributed consensus or Byzantine tamper resistance. Rolling back both the SQLite
file and the external head checkpoint remains undetectable, and an administrator with database write
access can rewrite and rehash the complete chain. Put the database on durable local storage with a
trusted parent directory, retain the external head in a stronger control plane, and keep proof keys in
a secret manager rather than alongside the database.

## Reproducible stale-promotion drill

The opt-in Compose profile runs a separate, ephemeral primary/replica pair on loopback ports 16379
and 16380. The drill first proves the replica is synchronized, redirects replication to a closed
loopback port, and then creates two claims on the isolated primary. The ungated claim is admitted;
the replica-gated claim is committed locally but admission is denied because `WAIT` receives no
acknowledgement. The drill shuts down the primary without persistence, promotes the stale replica,
and verifies that the same ungated digest can be admitted again while the replica-gated policy still
denies admission without an acknowledgement. It also creates an ephemeral signed promotion proof
whose required minimum is the detached primary's final offset. The stale promoted candidate is below
that floor, so the proof gate rejects it before the replay claim callback can run.

```bash
docker compose --profile redis-failover up -d --wait redis_fault_primary redis_fault_replica
python -m tools.redis_failover_drill \
  --primary-url redis://127.0.0.1:16379/0 \
  --replica-url redis://127.0.0.1:16380/0 \
  --receipt /tmp/redis-failover-receipt.json
docker compose --profile redis-failover down --volumes
```

The harness refuses non-loopback endpoints, embedded credentials, endpoint reuse and unbounded
timeouts before issuing `REPLICAOF` or `SHUTDOWN`. Its schema-v2 JSON receipt records policy outcomes,
replication offsets, the authority epoch, rejection reason and promotion-proof SHA-256—never claim
digests, HMAC keys, signatures, raw replication IDs, operation tokens or Redis URLs. CI executes the
live drill and retains the receipt artifact for 14 days; unit tests cover its safety boundary,
promotion verifier and private atomic receipt writer.

This deliberately demonstrates a limitation rather than claiming linearizability: `WAIT` protects
admission when the requested replica acknowledgement is unavailable, but it cannot select the
freshest replica or prevent an operator from promoting stale state. Production failover therefore
still requires freshness-aware orchestration or a strongly consistent conditional-write store. The
drill's signing key and epoch are ephemeral test inputs; production must source both from a durable
authority. The drill does not model Sentinel/Cluster elections, disk persistence, ACL rotation or
network healing.

## Sentinel election adapter

`tools/redis_sentinel_promotion.py` turns a live `SENTINEL MASTER` response and
the selected candidate's `INFO replication` document into a validated authority-ledger
decision. The adapter binds the configured master name and endpoint to Sentinel's 40-hex
run ID, requires a monotonic configuration epoch, rejects subjective/objective-down,
disconnected and in-progress failover states, bounds Sentinel INFO and ping age, and
checks that enough Sentinels are visible to satisfy the configured quorum. It also
requires the candidate to report `role=master` at or above an externally retained
replication-offset floor.

```python
from redis import Redis

from tools.redis_promotion_authority import SQLitePromotionAuthority
from tools.redis_sentinel_promotion import (
    SentinelPromotionPolicy,
    observe_sentinel_consensus,
)

sentinels = {
    name: Redis(host=name, port=26379, decode_responses=False)
    for name in ("sentinel-a", "sentinel-b", "sentinel-c")
}
candidate = Redis(host="10.0.0.12", port=6379, decode_responses=True)
policy = SentinelPromotionPolicy(
    master_name="replay-primary",
    candidate_host="10.0.0.12",
    candidate_port=6379,
    minimum_config_epoch=42,
)
decision = observe_sentinel_consensus(
    sentinels,
    candidate,
    policy,
    minimum_replication_offset=durable_pre_failover_offset,
    observed_at=trusted_unix_time,
)
state = decision.advance(
    SQLitePromotionAuthority("/var/lib/replay/authority.db", "edge-replay"),
    expected_state_sha256=externally_anchored_head,
)
```

The returned `source_sha256` commits to privacy-reduced topology evidence without
including the raw replication ID or endpoint. `decision.advance(...)` stores that commitment
in a version-2 ledger row and includes it in `state_sha256`. Consequently, a control-plane
checkpoint of the authority head also anchors the exact Sentinel evidence used for the
decision; tampering with either the source commitment or its row breaks chain validation.

`observe_sentinel_consensus` accepts 3–9 distinctly identified clients, obtains the candidate
replication snapshot once, and requires every configured observer to return the same candidate,
configuration epoch and candidate snapshot under the normal safety checks. Its combined commitment
is deterministic across mapping order and contains hashes of observer identifiers plus each
privacy-reduced source commitment. A missing, malformed, unsafe or dissenting view fails the whole
decision; no partial threshold is silently accepted. The single-observer function remains available
for deployments whose externally governed control plane already performs corroboration.

Matching observations and Sentinel's quorum/peer-count fields do **not** prove that a quorum voted
for a particular leader, that configured clients reach independent processes, or that an old primary
has been fenced. Sentinel also does not expose a safe replication-offset floor.
The caller must retain that floor before failover, use a trusted clock, connect to the
configured endpoints over an authenticated network, and anchor the ledger head in a
stronger control-plane store. The adapter does not initiate failover, discover arbitrary
endpoints, fence an old primary, implement consensus, or make Redis Sentinel Byzantine
fault tolerant.

### Disposable three-Sentinel election drill

Pull-request CI starts an isolated Redis primary, one synchronized replica and three independent
Sentinel processes. The drill writes and replica-acknowledges a synchronization marker, records the
resulting replication-offset floor, and commits the live primary into an initial authority head.
It then installs explicit `OUTPUT` drops from the primary only to the replica and three Sentinels.
Inbound packets are not dropped, and the bridge gateway is not a target, so the old primary remains
alive and writable from the host while its peer replies disappear. Replay admission remains closed
until all three Sentinels report the same promoted candidate at or above the retained offset floor.
The isolated bridge assigns stable lab-only addresses to the primary and replica. Sentinel can
therefore keep monitoring the stopped primary's address after Docker removes the container's DNS
record; the addresses are not production discovery guidance and are never included in the receipt.

The drill proves the still-live old primary accepts an isolated write that is absent from the new
primary, then advances the hash-chained authority ledger to the corroborated candidate. It issues a
short-lived proof from that exact head, verifies it against a fresh candidate snapshot, and executes
one replay claim. Proof verification and the
claim run inside an `IMMEDIATE` transaction on the external authority ledger. This prevents an epoch
advance from interleaving between authorization and the Redis write, while a stale head or candidate
is rejected before the write callback runs. Every protected write path must use this boundary; it
does not prevent clients that bypass the application fence from writing directly to Redis. Keep the
callback bounded because authority advances are serialized until it returns.

After admission, the controller removes every installed drop rule and waits for Sentinel to
reconfigure the old primary as a synchronized replica. The isolated write must not appear on the
promoted primary. Finally, the drill attempts an application write using the old authority head;
the SQLite epoch fence must reject the stale head before the callback is entered. Cleanup retries
rule removal in `finally`, while CI always tears down the disposable topology and volumes.

The archived receipt records
hashes, offsets, the authority epoch and boolean boundary results; it omits Redis/Sentinel endpoints,
raw run IDs, raw replication IDs, proof keys and replay tokens.

```bash
docker compose --profile redis-sentinel-election up -d --wait \
  redis_election_primary redis_election_replica \
  redis_election_sentinel_a redis_election_sentinel_b redis_election_sentinel_c
python -m tools.redis_sentinel_election_drill \
  --primary-url redis://127.0.0.1:16479/0 \
  --candidate-url redis://127.0.0.1:16480/0 \
  --sentinel-url redis://127.0.0.1:26479/0 \
  --sentinel-url redis://127.0.0.1:26480/0 \
  --sentinel-url redis://127.0.0.1:26481/0 \
  --candidate-advertised-host 172.30.0.11 \
  --candidate-advertised-port 6379 \
  --partition-peer 172.30.0.11 \
  --partition-peer 172.30.0.21 \
  --partition-peer 172.30.0.22 \
  --partition-peer 172.30.0.23 \
  --receipt /tmp/redis-sentinel-election-receipt.json
docker compose --profile redis-sentinel-election down --volumes
```

This proves the repository's corroboration, healing and stale-head rejection sequence against one
real Sentinel election and a kernel-enforced one-way egress partition. It is still a single-host
Docker bridge experiment, not an independent-machine network partition or distributed consensus
test. The topology has one promotion candidate, no post-promotion replica durability requirement,
no ACL/TLS boundary and no Byzantine-fault claim. The next step is to repeat the same receipt
contract across two network namespaces or hosts and inject delayed, reordered traffic during heal.


