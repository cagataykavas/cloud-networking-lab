# Bounded dual-stack connection racing

`tools/happy_eyeballs.py` contains an asynchronous TCP dialer for clients that already have a
snapshot of IPv4 and IPv6 destination addresses. It prevents a black-holed address family from
forcing users to wait for a complete serial timeout before the other family is tried.

The implementation follows the connection-racing portion of
[RFC 8305 (Happy Eyeballs v2)](https://www.rfc-editor.org/rfc/rfc8305.html):

- canonicalize and deduplicate IP literals;
- preserve resolver order within each family while interleaving IPv6 and IPv4 candidates;
- start one attempt immediately and stagger later attempts instead of opening every socket at once;
- use the RFC's 250 ms recommended attempt delay by default and reject values below its 10 ms
  mandatory lower bound;
- cancel losing attempts as soon as one connection succeeds;
- enforce one global monotonic deadline and a bounded candidate count;
- keep the original hostname separate from the selected IP so TLS callers retain SNI and hostname
  verification;
- expose structured attempt evidence without copying exception text into reports.

## Library use

```python
import asyncio
import socket

from tools.happy_eyeballs import open_happy_eyeballs_connection


async def connect(host: str, port: int):
    answers = await asyncio.to_thread(
        socket.getaddrinfo,
        host,
        port,
        0,
        socket.SOCK_STREAM,
    )
    addresses = [row[4][0] for row in answers]
    result = await open_happy_eyeballs_connection(host, port, addresses)
    return result.reader, result.writer, result.report
```

For TLS, pass a verified `ssl.SSLContext`. The default connector dials the selected IP address but
passes `host` as `server_hostname`, so address racing does not weaken certificate verification.

## Deliberate boundaries

This is a connection-racing component, not a complete RFC 8305 resolver. DNS acquisition remains
with the caller so it can enforce its own caching, DNSSEC, split-horizon and SSRF policy. The module
does not implement asynchronous A/AAAA query arrival, RFC 6724 source/destination selection,
historical RTT preference, NAT64 synthesis, proxy negotiation or application-protocol validation.

Cancellation also cannot guarantee that an arbitrary third-party connector releases resources; the
default `asyncio` connector is cancellation-aware, while injected connectors remain responsible for
their own cleanup. Operators should retain per-family success/latency metrics because successful
fallback can otherwise hide a persistent routing fault.
