# Load-balancer evidence gate

`tools/load_demo.py` makes reverse-proxy behavior measurable. The evidence gate
turns that JSON into a deterministic release decision instead of treating a
single successful request as proof that the whole backend pool is healthy.

```bash
python tools/load_demo.py --requests 100 --concurrency 16 > load-report.json
python tools/load_balance_gate.py load-report.json \
  --backend backend-a \
  --backend backend-b
```

Exit code `0` admits the evidence, `2` reports a valid policy rejection and `3`
identifies malformed or inconsistent evidence. The JSON report contains stable
reason codes for automation.

## Decision contract

The default policy requires at least 100 attempted requests. It uses the lower
bound of a 95% Wilson confidence interval rather than accepting the raw success
ratio, so a tiny perfect sample cannot promote a deployment. It also requires:

- every expected backend to receive traffic;
- no unexpected backend unless explicitly allowed;
- no backend to exceed its uniform share by more than 20 percentage points;
- p95 latency at or below 250 ms;
- internally consistent request, failure and backend counts.

These controls distinguish total backend loss from partial traffic skew and from
client-visible reliability or tail-latency regressions.

## Trust boundary and limitations

The gate trusts the load generator's backend identity and latency measurements.
Use request IDs and signed/retained CI artifacts when stronger provenance is
required. Least-connections balancing is not expected to be perfectly uniform:
request duration, keep-alive reuse, connection pooling and a small sample can all
create legitimate skew. Calibrate the share and latency budgets with a stable
baseline rather than claiming the defaults are universal SLOs.

This is client-side evidence, not packet capture or load-balancer telemetry. It
cannot prove route symmetry, distinguish proxy time from application time, or
detect a backend that returns a false healthy identity. A production next step
is to correlate request IDs with Nginx upstream logs and per-backend metrics.
