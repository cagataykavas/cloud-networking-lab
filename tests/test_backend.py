from fastapi.testclient import TestClient

from app.backend import app
from tools.network_probe import probe


def test_backend_health() -> None:
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["instance_id"]


def test_echo_round_trip() -> None:
    client = TestClient(app)
    response = client.post("/echo", json={"message": "hello-network"})
    assert response.status_code == 200
    assert response.json()["message"] == "hello-network"


def test_probe_rejects_invalid_scheme() -> None:
    try:
        probe("ftp://example.com")
    except ValueError as exc:
        assert "http" in str(exc)
    else:
        raise AssertionError("invalid URL scheme should fail")
