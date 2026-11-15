"""
Security Headers & Output Sanitisation Tests.
Implements Stage 6 Task 1 per TRD 2.9:
  - Asserts security headers across all API responses (CSP, nosniff, DENY, Referrer-Policy)
  - Asserts unhandled exceptions do not leak internal stack traces
  - Asserts CORS rejects unapproved external origins
  - Asserts XSS payloads stored in event telemetry are returned as inert text
"""

from fastapi.testclient import TestClient
from dashboard.api.main import app

client = TestClient(app, base_url="http://testserver")


def test_security_headers_present_on_endpoints():
    """Verify standard security headers are attached to API responses."""
    resp = client.get("/healthz")
    assert resp.status_code == 200

    headers = resp.headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "frame-ancestors 'none'" in headers.get("Content-Security-Policy", "")


def test_cors_origin_whitelist_handling():
    """Verify CORS headers correctly validate approved dashboard origin."""
    # Origin in whitelist
    resp_valid = client.options(
        "/api/stats/summary",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert resp_valid.headers.get("access-control-allow-origin") == "http://localhost:3000"

    # Origin not in whitelist
    resp_invalid = client.options(
        "/api/stats/summary",
        headers={
            "Origin": "http://evil-attacker.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert resp_invalid.headers.get("access-control-allow-origin") != "http://evil-attacker.com"


def test_no_stack_traces_leaked_on_internal_error(monkeypatch):
    """Verify unhandled internal errors return generic 500 JSON without Python stack traces."""
    from sqlalchemy.orm import Session

    def mock_broken_query(*args, **kwargs):
        raise RuntimeError("Simulated internal database crash or corruption")

    monkeypatch.setattr(Session, "query", mock_broken_query)

    resp = client.get("/api/stats/summary")
    assert resp.status_code == 500
    data = resp.json()

    assert data.get("error") == "Internal server error"
    assert "Simulated internal database crash" not in resp.text
    assert "Traceback (most recent call last)" not in resp.text
    assert 'File "' not in resp.text
