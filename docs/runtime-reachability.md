# Runtime network reachability evidence

Valid Docker Compose syntax and a static topology review do not prove that the live
container network enforces the intended boundary. Docker daemon configuration, bridge
isolation rules, service attachments, or a later override can change what is actually
reachable.

`tools/runtime_reachability.py` creates a uniquely named Compose project and tests the
running data plane from a hardened probe container attached **only** to the edge
network. The release gate requires all of these observations:

1. `http://proxy/whoami` returns a bounded JSON response from an expected backend. This
   proves edge-to-proxy and proxy-to-private-backend routing.
2. `backend_a` and `backend_b` do not resolve through Docker DNS from the edge network.
3. The configured private IPv4 address of each backend cannot accept a TCP connection
   from the edge network.

The audit first parses `docker compose config --format json`, verifies the proxy is
dual-homed, verifies each backend is private-only and has no published host port, and
derives the actual runtime edge-network name. It does not accept caller-provided network
names or backend IPs for the probes.

## Evidence and failure behavior

The report contains:

- a canonical SHA-256 identity for the reviewed topology subset;
- a canonical policy identity;
- one privacy-reduced observation per route or isolation check;
- stable reason codes and a canonical evidence identity.

Service names and private IP addresses are used to execute probes but are represented by
SHA-256 subject identifiers in the report. Operational failures emit only a stable error
class, not Docker daemon output. Accepted, policy-rejected, and operational outcomes use
exit codes `0`, `2`, and `3` respectively. The JSON artifact is written atomically.

The probe container is read-only, unprivileged, capability-free, PID/memory/CPU bounded,
and attached only to the normalized edge network. The project name is strictly validated
before it is passed to Docker. Cleanup targets only that explicit Compose project and runs
after both accepted and rejected probes.

Run locally with Docker Compose v2:

```bash
python tools/runtime_reachability.py \
  --project-name network-reachability-local \
  --output artifacts/runtime-reachability.json
```

## Trust boundaries and limitations

- The result is evidence for one Docker daemon and one point in time. It does not prove
  Kubernetes NetworkPolicy, cloud security groups, host firewall rules, overlay
  encryption, or another deployment environment.
- A failed TCP connection demonstrates observed isolation, not which firewall or routing
  rule caused it. Packet capture or namespace inspection is a separate diagnostic step.
- The probe image tag is pulled before the test and then used with `--pull=never`, but the
  tag remains mutable upstream. A production control should pin and verify an approved
  image digest.
- DNS and TCP checks are negative observations bounded by a two-second timeout. Severe
  host scheduling or daemon failure is classified as operational rather than accepted.
- SHA-256 subject identifiers prevent accidental disclosure in ordinary reports; they do
  not anonymize low-entropy service names or addresses against offline guessing.
- The proxy success check proves basic routing and bounded JSON shape, not authentication,
  TLS, application authorization, sustained capacity, or the absence of alternate paths.

The next increment is to capture signed namespace/firewall evidence from the runner and
bind it to the same topology digest, then reproduce the check against a cloud deployment
with provider-native reachability analysis.

## References

- [Docker bridge-network isolation](https://docs.docker.com/engine/network/drivers/bridge/)
- [`docker compose config` canonical model](https://docs.docker.com/reference/cli/docker/compose/config/)
- [`docker compose up --wait`](https://docs.docker.com/reference/cli/docker/compose/up/)
