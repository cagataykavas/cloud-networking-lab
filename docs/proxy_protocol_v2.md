# PROXY protocol v2 admission

Layer-4 load balancers often open a new TCP connection to an application, so the
application socket sees the load balancer rather than the original client. PROXY
protocol v2 can carry the original endpoints in a binary preamble, but those bytes
are claims, not proof. A client that reaches a PROXY-aware listener directly can
otherwise forge them.

`tools/proxy_v2.py` implements the narrow admission boundary that must run before
an HTTP/TLS parser consumes any application bytes:

1. Trust the header only when the actual socket peer belongs to an explicit proxy
   CIDR.
2. Require v2 `PROXY` over IPv4/TCP or IPv6/TCP; reject `LOCAL`, datagrams and
   unspecified transports.
3. Bind the claimed destination to configured listener CIDRs and ports so a valid
   header cannot be replayed across services.
4. Bound the complete header, TLV count and unique-ID size before exposing the
   forwarded endpoints.
5. Allow-list TLV types, reject duplicate singleton TLVs, and verify the optional
   protocol CRC-32C integrity TLV. The default policy requires it.
6. Return source and destination endpoints only to the in-process caller. Emitted
   evidence contains hashes and low-cardinality protocol facts, not raw addresses
   or unique IDs.

## Library use

Read exactly one preamble from the accepted byte stream, then admit it with the
kernel-observed peer address:

```python
from tools.connection_limiter import ConnectionLimitPolicy, ConnectionLimiter
from tools.listener_admission import admit_listener_connection
from tools.proxy_v2 import ProxyV2Policy
from tools.replay_guard import ProxyReplayGuard, ReplayGuardPolicy

policy = ProxyV2Policy.from_strings(
    trusted_proxy_cidrs=("10.10.0.0/24",),
    destination_cidrs=("10.20.0.0/24",),
    destination_ports=(8443,),
)

limiter = ConnectionLimiter(ConnectionLimitPolicy(max_in_flight=256))
replay_guard = ProxyReplayGuard(
    ReplayGuardPolicy(ttl_seconds=300, max_entries=65_536)
)

# The adapter acquires immediately, admits the preamble under one deadline, and
# releases capacity on every rejected/error path. Acceptance retains the lease.
with admit_listener_connection(
    accepted_socket,
    immediate_peer=socket_peer_ip,
    limiter=limiter,
    proxy_policy=policy,
    replay_guard=replay_guard,
    read_timeout_seconds=0.250,
) as result:
    emit_structured_log(result.evidence.as_dict())
    if result.accepted:
        handle_application_connection(result.metadata)
    else:
        close_connection_without_parsing_application_bytes()
```

The listener must derive `socket_peer_ip` from the accepted socket, never from the
header or an HTTP field. On any malformed or rejected result it must close the
connection; silently falling back to the socket peer creates an ambiguous protocol
boundary. `read_proxy_v2_socket` applies one monotonic deadline across every
partial `recv`, tightens the socket timeout to the remaining budget, and restores
the prior timeout before returning. A timeout raises
`HeaderReadDeadlineExceeded`; the listener must close that connection without
passing any bytes to the application parser. The deadline is capped at 30 seconds
to prevent accidental unbounded configuration.

`ConnectionLimiter.acquire()` is deliberately non-blocking: when every handler slot
is occupied it raises `connection_capacity_exceeded`, and the listener must close
the newly accepted socket without reading its preamble. Queuing there would create
a second wait outside the preamble deadline. A lease is released on normal return
or exception, repeated cleanup is idempotent, and snapshots expose only a fixed,
low-cardinality metric set: in-flight, available, admitted, rejected and high-watermark.
The policy permits 1–65,536 slots and has a deterministic SHA-256 identifier.

`admit_listener_connection` composes both controls into one fail-closed boundary.
Capacity exhaustion is decided before any socket read. All failures after lease
acquisition release the slot, while an accepted result retains it until explicit
release or context-manager exit. Its structured evidence binds the capacity policy,
PROXY policy, optional replay policy and parser evidence digests without recording
raw IP addresses, ports, unique IDs or internal lease tokens. When configured, the
replay guard requires a UNIQUE_ID TLV and rejects a repeated hashed identifier or a
full bounded claim set before application handling. The evidence digest detects
edited records but is not an authentication mechanism; ship logs over an
authenticated channel and protect the destination against deletion or rollback.

## Offline audit CLI

The CLI checks a binary header against a JSON policy and emits privacy-reduced,
deterministic evidence:

```bash
python tools/proxy_v2.py captured-header.bin \
  --peer 10.10.0.12 \
  --policy proxy-policy.json
```

Exit codes are `0` for accepted, `2` for policy-rejected and `3` for malformed or
operational input. Policy JSON accepts `trusted_proxy_cidrs`,
`destination_cidrs`, `destination_ports`, `allowed_tlv_types`, `require_crc32c`,
`max_header_bytes`, `max_tlvs` and `max_unique_id_bytes`. Unknown fields fail
closed. Policy input is capped at 64 KiB; duplicate keys and non-finite values are
rejected instead of inheriting permissive JSON-parser behavior.

## Trust boundaries and limitations

- CRC-32C detects accidental corruption; it is not authentication. Network policy,
  security groups or mTLS must ensure only the expected load balancer can occupy a
  trusted source CIDR.
- Forwarded client addresses are useful for routing, logging and rate limiting but
  are not sufficient authorization identities.
- The parser deliberately rejects Unix sockets, UDP, `LOCAL`, nested SSL TLVs and
  unconfigured extensions. Enable additional TLVs only after validating their
  exact format and defining their trust semantics.
- This module does not configure Nginx, HAProxy, Uvicorn or a cloud load balancer.
  Producer/consumer versions and whether a CRC TLV is emitted must be tested in the
  deployed path.
- The limiter caps sockets admitted to application handlers; it does not bound the
  kernel accept backlog, process file descriptors, SYN queue, load-balancer retries
  or capacity across multiple processes/hosts. Those need separate OS and
  infrastructure limits plus aggregation of per-worker metrics.
- Hashes are evidence identifiers, not secrecy controls; low-entropy headers may be
  guessable and evidence still requires access control.

The next integration step is a pinned proxy container that sends real preambles
through this adapter, proves application bytes remain framed, and exports the
evidence to an authenticated append-only log destination.
