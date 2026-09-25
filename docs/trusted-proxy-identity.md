# Trusted proxy client identity

`X-Forwarded-For` is caller-controlled input unless the immediate connection peer is an explicitly
trusted proxy. Treating its leftmost value as the client lets a direct caller or an attacker-prepended
entry spoof source identity in logs, rate limits, fraud controls, or authorization decisions.

The backend now derives client identity with this contract:

1. The socket peer is always authoritative when it is outside `TRUSTED_PROXY_CIDRS`; any forwarded
   header is ignored.
2. A trusted peer must supply a syntactically valid forwarded chain.
3. The chain is walked from right to left, removing only explicitly trusted proxy hops.
4. The first untrusted address is the derived client. Attacker-prepended values further left do not
   override it.
5. Missing, malformed, oversized, overlong, or all-trusted chains produce no client identity and a
   stable evidence code.

Only plain IPv4 and IPv6 literals are accepted. Ports, zone identifiers, hostnames, `unknown`, empty
elements, and quoted extensions are deliberately rejected instead of being guessed. Limits default
to 16 hops and 4 KiB. The response reports counts and a status code without echoing the raw chain.

## Configuration

The Docker topology sets the backend policy to its dedicated proxy-facing network:

```yaml
TRUSTED_PROXY_CIDRS: 172.29.0.0/24
```

Multiple canonical CIDRs may be comma-separated. Empty configuration trusts no proxies. CIDRs broader
than `/8` for IPv4 or `/32` for IPv6 are rejected at startup to prevent an accidental trust-all policy.
Production deployments should use the narrow addresses or subnets assigned to their ingress tier and
update them transactionally with network changes.

The current Nginx configuration appends its observed `$remote_addr` to the header. This is compatible
with right-to-left evaluation: a client-supplied prefix remains to the left of the address observed by
the trusted proxy and cannot become authoritative.

## Boundaries

This utility authenticates no person and proves no network path cryptographically. The result is safe
only while direct access to the application is controlled, proxy address allocation is trustworthy,
and every trusted hop follows the append/overwrite contract. Uvicorn or another framework must not
rewrite the socket peer from forwarded headers before this check. Managed load balancer address ranges
also change over time and need a controlled update process.

Use the derived value for observability or as one signal in abuse controls. Do not make high-impact
authorization decisions from an IP address alone. A next step is signed proxy metadata or mTLS-bound
ingress identity plus metrics for every rejection status.
