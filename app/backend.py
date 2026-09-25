from __future__ import annotations

import os
import socket
import time
from datetime import datetime, timezone

from fastapi import FastAPI, Header, Request
from pydantic import BaseModel

from app.proxy_trust import ProxyEvidenceError, TrustedProxyPolicy, resolve_client_identity


class EchoRequest(BaseModel):
    message: str


INSTANCE_ID = os.getenv("INSTANCE_ID", socket.gethostname())
STARTED_AT = time.monotonic()


def _proxy_policy_from_environment() -> TrustedProxyPolicy:
    raw = os.getenv("TRUSTED_PROXY_CIDRS", "")
    if not raw:
        return TrustedProxyPolicy()
    values = raw.split(",")
    if any(not value.strip() for value in values):
        raise ValueError("TRUSTED_PROXY_CIDRS contains an empty entry")
    cidrs = tuple(value.strip() for value in values)
    return TrustedProxyPolicy(trusted_proxy_cidrs=cidrs)


TRUSTED_PROXY_POLICY = _proxy_policy_from_environment()

app = FastAPI(
    title="Cloud Networking Lab Backend",
    version="1.0.0",
    description="Inspectable backend used behind Nginx to demonstrate DNS, routing, load balancing and failure behavior.",
)


@app.get("/health")
def health() -> dict[str, object]:
    return {
        "status": "ok",
        "instance_id": INSTANCE_ID,
        "hostname": socket.gethostname(),
        "uptime_seconds": round(time.monotonic() - STARTED_AT, 3),
    }


@app.get("/whoami")
def whoami(request: Request, x_request_id: str | None = Header(default=None)) -> dict[str, object]:
    client_host = request.client.host if request.client else None
    forwarded_for = request.headers.get("x-forwarded-for")
    try:
        identity = resolve_client_identity(client_host, forwarded_for, TRUSTED_PROXY_POLICY)
        client_ip = identity.client_ip
        client_ip_source = identity.source
        proxy_evidence_status = identity.status
        forwarded_hop_count: int | None = identity.forwarded_hop_count
        trusted_proxy_hop_count: int | None = identity.trusted_proxy_hop_count
    except ProxyEvidenceError as exc:
        client_ip = None
        client_ip_source = "unattributed"
        proxy_evidence_status = exc.code
        forwarded_hop_count = None
        trusted_proxy_hop_count = None
    return {
        "instance_id": INSTANCE_ID,
        "hostname": socket.gethostname(),
        "client_host": client_host,
        "client_ip": client_ip,
        "client_ip_source": client_ip_source,
        "proxy_evidence_status": proxy_evidence_status,
        "forwarded_hop_count": forwarded_hop_count,
        "trusted_proxy_hop_count": trusted_proxy_hop_count,
        "request_id": x_request_id,
        "forwarded_proto": request.headers.get("x-forwarded-proto"),
        "server_time": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/echo")
def echo(payload: EchoRequest) -> dict[str, str]:
    return {"instance_id": INSTANCE_ID, "message": payload.message}


@app.get("/delay/{milliseconds}")
def delay(milliseconds: int) -> dict[str, object]:
    bounded = max(0, min(milliseconds, 5000))
    time.sleep(bounded / 1000)
    return {"instance_id": INSTANCE_ID, "delay_ms": bounded}
