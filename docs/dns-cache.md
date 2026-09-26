# Bounded DNS cache and refresh policy

`tools/dns_cache.py` is a dependency-free asynchronous DNS cache for clients that need explicit control over resolver load and stale-answer behavior. It is designed to sit between an approved resolver adapter and a connection layer such as the repository's bounded dual-stack dialer.

## Reliability behavior

- Positive TTLs are clamped to configured minimum and maximum bounds using a monotonic clock.
- A and AAAA answers are family-checked, canonicalized and deduplicated under an address-count budget.
- Concurrent misses for the same `(hostname, qtype)` share one shielded refresh task, preventing a cache stampede and preventing one cancelled waiter from cancelling every caller's lookup.
- Distinct refresh work is capped by `max_inflight`; cache state is bounded by an LRU `max_entries` budget.
- NXDOMAIN and NODATA are cached for a bounded negative TTL and never replaced by a stale positive answer.
- Timeouts, SERVFAIL-style retryable failures, invalid adapter responses and unknown exceptions receive a short backoff entry. A previously valid answer may be served only inside the configured stale-if-error window.
- Provider exception text, hostnames and raw addresses are omitted from structured evidence. Host and address identities use SHA-256 digests.

The resolver adapter returns `ResolverAnswer(addresses, ttl_seconds)` or raises a typed `ResolverFailure`. Only NXDOMAIN and NODATA may be permanent; other explicit failures must be marked retryable. Invalid contracts fail closed with stable public error codes.

## Trust and security boundaries

This cache does not decide whether an address is safe to contact. Callers must still apply the egress policy to every refreshed DNS snapshot, pin the actual connection to an admitted address, preserve the original hostname for TLS SNI/certificate verification, and revalidate redirects. A stale answer is a reliability tradeoff and should be disabled or tightly bounded where rapid DNS revocation is part of the security model.

The implementation is process-local. Replicas do not share cache state or single-flight work, and resolver TTLs are trusted only within configured clamps. DNSSEC validation, search-domain expansion, CNAME-chain policy, NAT64 synthesis, RFC 6724 ordering and system resolver configuration belong to the resolver/connection adapters.

## Next integration step

Add an opt-in resolver adapter to `network_probe.py`, then pass each returned A/AAAA snapshot through the existing egress admission boundary before the dual-stack connector is allowed to race addresses. Export cache hit, stale serve, negative hit, refresh failure and in-flight rejection counters without hostname labels.
