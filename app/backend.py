from __future__ import annotations

import os
import socket
import time
from datetime import datetime, timezone

from fastapi import FastAPI, Header, Request
from pydantic import BaseModel

from app.client_identity import parse_trusted_proxy_cidrs, resolve_client_identity


class EchoRequest(BaseModel):
    message: str


INSTANCE_ID = os.getenv("INSTANCE_ID", socket.gethostname())
STARTED_AT = time.monotonic()
TRUSTED_PROXY_NETWORKS = parse_trusted_proxy_cidrs(os.getenv("TRUSTED_PROXY_CIDRS", ""))

app = FastAPI(
    title="Cloud Networking Lab Backend",
    version="1.1.0",
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
def whoami(
    request: Request, x_request_id: str | None = Header(default=None)
) -> dict[str, object]:
    client_host = request.client.host if request.client else None
    identity = resolve_client_identity(
        client_host,
        request.headers.get("x-forwarded-for"),
        TRUSTED_PROXY_NETWORKS,
    )
    return {
        "instance_id": INSTANCE_ID,
        "hostname": socket.gethostname(),
        "client_host": client_host,
        "peer_ip": client_host,
        "client_ip": identity.client_ip,
        "client_ip_source": identity.source,
        "forwarded_header_accepted": identity.forwarded_header_accepted,
        "client_identity_error": identity.error,
        "request_id": x_request_id,
        "forwarded_for": request.headers.get("x-forwarded-for"),
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
