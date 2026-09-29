# Compose network topology audit

The runnable lab relies on one security property: the reverse proxy is the only host-published
service and the only bridge between the edge and internal application networks. A valid YAML file
does not prove that property. A later debug service, host-network override, published backend port,
or overlapping subnet can silently bypass the intended boundary.

`tools/topology_audit.py` evaluates Docker Compose's normalized JSON rather than parsing YAML itself.
That makes Compose interpolation and merge resolution part of the evidence being checked.

```bash
docker compose config --format json > /tmp/compose.json
python tools/topology_audit.py /tmp/compose.json \
  --backend-service backend_a \
  --backend-service backend_b
```

The command exits `0` when the topology is admitted, `2` for a policy rejection, and `3` for a
malformed or over-budget artifact. Its JSON report includes bounded reason codes plus canonical
SHA-256 identities for the security-relevant topology projection and policy. Machine-specific
volume source paths are intentionally excluded from that projection.

## Enforced boundary

- the proxy is attached to exactly `edge` and `private_app`;
- every declared backend is attached only to `private_app`;
- no unreviewed service is present;
- only the proxy publishes a host port, and it publishes the expected TCP target;
- the private network is `internal`, while the edge network is not;
- audited networks use the bridge driver and are not external;
- declared subnets are canonical, non-overlapping, and contain every static address;
- static addresses are unique;
- host networking, privileged containers, and `NET_ADMIN`, `NET_RAW`, or `SYS_ADMIN` additions are
  rejected;
- document, service, network, and attachment counts are bounded before analysis.

CI pipes `docker compose config --format json` into the audit, so drift fails before an image is
published or a topology is exercised.

## Trust boundary and limitations

This is a static desired-state check. It does not inspect live Linux namespaces, iptables/nftables,
Docker daemon policy, cloud security groups, overlay-network encryption, DNS answers, or a deployed
host's existing containers. It also cannot prove that the proxy is free of application-layer routing
bugs. Production rollout should pair it with least-privilege host controls and a runtime reachability
probe that verifies backends are unreachable from the edge while the proxy path remains healthy.
