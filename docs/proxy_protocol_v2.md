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
from tools.proxy_v2 import ProxyV2Policy, admit_proxy_v2, read_proxy_v2_header

policy = ProxyV2Policy.from_strings(
    trusted_proxy_cidrs=("10.10.0.0/24",),
    destination_cidrs=("10.20.0.0/24",),
    destination_ports=(8443,),
)

header = read_proxy_v2_header(stream, max_header_bytes=policy.max_header_bytes)
result = admit_proxy_v2(header, immediate_peer=socket_peer_ip, policy=policy)
if not result.accepted:
    close_connection_without_parsing_application_bytes()
metadata = result.metadata
```

The listener must derive `socket_peer_ip` from the accepted socket, never from the
header or an HTTP field. On any malformed or rejected result it must close the
connection; silently falling back to the socket peer creates an ambiguous protocol
boundary. Enforce a read deadline around `read_proxy_v2_header` in the serving
runtime to prevent slow-preamble connection exhaustion.

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
- Hashes are evidence identifiers, not secrecy controls; low-entropy headers may be
  guessable and evidence still requires access control.

The next integration step is a loopback TCP fixture or pinned proxy container that
sends real preambles into a small adapter, proves application bytes remain framed,
and binds the accepted evidence digest to connection logs.
