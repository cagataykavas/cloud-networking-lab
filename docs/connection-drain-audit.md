# Connection-drain release audit

A backend process being healthy before termination does not prove that a rollout drained it safely.
The load balancer may continue opening connections after readiness withdrawal, endpoints may take too
long to disappear, in-flight work may be killed, or too many backends may drain at once.

`tools/connection_drain_audit.py` evaluates a bounded JSON trace after a rollout. It expects one
record per retiring backend with lifecycle timestamps and interval connection samples. The gate
checks:

- replacement capacity became ready before old readiness was withdrawn;
- endpoint removal followed readiness withdrawal within a budget;
- the drain window was long enough, but not unbounded;
- sampling covered the lifecycle without evidence gaps;
- no new connection was admitted after endpoint propagation grace;
- active connections and in-flight requests reached zero before termination;
- request failures and concurrent drains stayed inside policy.

All timestamps must be timezone-aware. Counts are non-negative integers; `new_connections` and
`failed_requests` are interval counts ending at `observed_at`. Samples must be strictly ordered.
Malformed evidence exits `3`, a policy rejection exits `2`, and acceptance exits `0`.

```bash
python tools/connection_drain_audit.py rollout-drain.json \
  --now 2026-09-26T19:00:00Z \
  --min-drain-seconds 30 \
  --max-concurrent-drains 1
```

Reports contain stable reason codes plus hashed backend/deployment references. The canonical artifact
digest is independent of backend list order and UTC-offset spelling, which makes it suitable for CI
evidence comparison without publishing infrastructure identifiers. Reports retain at most 128
findings and explicitly mark truncation.

## Trust boundaries and limitations

- The evaluator trusts its collector. Metrics must come from the proxy/load balancer and workload
  control plane, not from the terminating process alone.
- Aggregate samples can hide short connection spikes between observations. Use a sampling cadence
  materially shorter than the propagation and termination budgets.
- `replacement_ready_at` is readiness evidence, not proof of spare capacity, zone diversity, or
  successful traffic. Combine this gate with capacity and load-balancer health checks.
- Connection counters do not prove application transaction completion. Long-lived streams and
  WebSockets need protocol-aware shutdown acknowledgement.
- The gate audits a completed rollout; it does not stop one in real time. Production automation
  should pause subsequent waves on the first rejection and retain the raw, access-controlled trace.
- SHA-256 references reduce accidental identifier disclosure but do not anonymize low-entropy names.
  Use governed opaque IDs or keyed digests when dictionary inference matters.

The next production step is a least-privilege collector that joins orchestrator lifecycle events,
load-balancer connection counters, and request failures into this artifact and signs it before the
release gate evaluates it.
