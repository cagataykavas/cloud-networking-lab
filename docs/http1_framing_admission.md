# HTTP/1.1 framing admission

Reverse proxies and application servers can interpret an ambiguous HTTP/1.1
request differently. If one component treats a byte sequence as the end of one
request while the next component treats it as part of another, an attacker may
desynchronize the connection and smuggle a request across the trust boundary.

`tools/http1_framing.py` is a dependency-free, fail-closed conformance gate for
the request head that a proxy is about to forward. It is intentionally narrower
than a general HTTP implementation: accepting fewer encodings is preferable to
letting two components disagree.

## What the gate enforces

- exact CRLF line endings and one terminal CRLF-CRLF delimiter;
- bounded head, line, field-count and declared-body sizes;
- valid request-line, header-name and field-value octets;
- exactly one non-empty `Host` field for HTTP/1.1;
- no obsolete line folding, `Proxy-Connection`, or framing fields nominated by
  `Connection`;
- at most one canonical `Content-Length`, with no comma list, sign, extra
  whitespace, or leading zero;
- at most one `Transfer-Encoding`, ending in one `chunked` coding and containing
  only explicitly allowed codings;
- unconditional rejection of `Transfer-Encoding` plus `Content-Length`;
- no HTTP/1.0 transfer coding, bodyless `Expect: 100-continue`, or `Trailer`
  without chunked framing.

The JSON report contains stable reason codes and SHA-256 digests of the request
head and policy. It does **not** contain the request target, host, or header
values. This keeps CI and admission evidence useful without copying credentials
or tenant identifiers into logs.

The digests are evidence identifiers, not a confidentiality mechanism. A value
with a small guessable input space can still be tested offline, so reports
should retain the same access controls as other security telemetry.

## Usage

Capture the exact request head after edge TLS termination but before backend
forwarding. The file must stop after the first header delimiter; body bytes are
not accepted because auditing one byte sequence and forwarding another would
invalidate the result.

```bash
python -m tools.http1_framing request-head.bin --output framing-report.json
```

Exit codes are stable for automation:

| Code | Meaning |
|---:|---|
| `0` | unambiguous request head accepted |
| `2` | request rejected by syntax, resource, or framing policy |
| `3` | local I/O or policy configuration error |

For in-process use, pass an immutable policy explicitly:

```python
from tools.http1_framing import FramingPolicy, audit_request_head

report = audit_request_head(
    raw_head,
    FramingPolicy(max_body_bytes=1_048_576),
)
if not report.accepted:
    close_connection_without_forwarding(report.reason_codes)
```

## Deployment boundary

This gate is a conformance aid, not a replacement for a maintained proxy or
HTTP server. Production enforcement must run on the exact bytes forwarded on a
connection, and a rejection must close that connection rather than attempt to
recover its parser state. Every hop should use the same strict framing policy;
normalizing a rejected request and forwarding it can reintroduce the ambiguity.

The implementation audits the request head only. It does not decode chunk
frames, validate trailers, terminate TLS, authenticate peers, or prove that a
specific proxy/backend pair has identical parsers. The next useful increment is
a differential integration test that replays the accepted/rejected corpus
through the pinned Nginx and application-server versions used by the lab.
