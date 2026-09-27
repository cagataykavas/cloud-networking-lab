# mTLS rotation readiness audit

Certificate rotation is a distributed state transition, not a file replacement. Removing an old trust root before every client trusts the new root can create an outage; presenting a new leaf before its chain is trusted has the same effect. `tools/mtls_rotation_audit.py` turns normalized handshake evidence into a deterministic admission decision before the old root is removed.

## Required transition

The artifact contains exactly three causally ordered phases:

1. `dual_trust_old_leaf`: all clients trust both roots while every server still presents the old leaf.
2. `dual_trust_new_leaf`: both roots remain trusted while every server presents the new leaf and verifies through the new root.
3. `new_trust_only`: all clients trust only the new root and all servers continue to present the new leaf.

For every phase, the gate requires the full configured client × server-instance matrix. It checks the phase-wide trust bundle, per-client observed trust bundle, presented leaf, verified root, per-pair handshake budget, aggregate failure rate and exact instance coverage. It also enforces:

- non-overlapping chronological phase intervals and a minimum dual-trust window;
- leaf issuer, service identity SAN and `serverAuth` EKU bindings;
- validity at collection time and a minimum remaining lifetime for the new chain;
- RSA ≥ 2048, ECDSA ≥ 256, or Ed25519 key policy;
- fresh UTC evidence with bounded future skew;
- duplicate-free JSON, finite numbers, strict members, exact count reconciliation and a 128 KiB input limit.

## Artifact contract

Fingerprints are lowercase SHA-256 hex. CA inventory entries are self-issued normalized trust anchors; leaf entries reference their issuer fingerprint. `required_clients` and `required_instances` are stable collector IDs, not display names. Each client/instance pair appears exactly once per phase.

An observation has the following shape:

```json
{
  "client_id": "edge-a",
  "instance_id": "api-a",
  "trusted_ca_fingerprints": ["<old-ca-sha256>", "<new-ca-sha256>"],
  "presented_leaf_fingerprint_sha256": "<new-leaf-sha256>",
  "verified_ca_fingerprint_sha256": "<new-ca-sha256>",
  "attempts": 100,
  "successes": 100,
  "failure_codes": {}
}
```

Failed attempts must be represented by stable, non-sensitive codes and their counts must equal `attempts - successes`. The policy limits are part of the input and are covered by `policy_sha256`; the complete normalized artifact is covered by `artifact_sha256`.

Run the audit with an explicit evaluation time when reproducibility matters:

```bash
python tools/mtls_rotation_audit.py rotation-evidence.json \
  --at 2026-09-27T07:00:00Z > rotation-report.json
```

Exit codes are stable for automation:

| Code | Meaning |
|---:|---|
| `0` | Evidence is well formed and the rotation is accepted. |
| `2` | Evidence is well formed, but one or more policy findings reject the rotation. |
| `3` | Evidence is malformed, ambiguous, non-finite, oversized or incomplete. |

The report hashes the rotation ID, service identity and policy version instead of copying them. Finding codes never include raw certificate, client, instance or failure data. `evidence_sha256` covers the canonical report, including the evaluation time.

## Collector and enforcement boundary

This gate deliberately consumes normalized evidence. It does **not** parse PEM/DER, validate a cryptographic signature, prove possession of a private key, contact OCSP/CRL endpoints, negotiate TLS, attest client clocks or mutate a proxy configuration. A production collector should obtain certificate chains and negotiated outcomes from authenticated Envoy, Nginx, service-mesh or active-probe telemetry; sign the artifact; and bind it to the exact deployment intent.

Admission must run in the control-plane path that removes the old root. A successful report is not useful if an operator can bypass it or if the observed client/server inventory is incomplete. The next increment is a signed collector adapter plus transactional binding between the accepted evidence digest and the trust-bundle rollout operation.
