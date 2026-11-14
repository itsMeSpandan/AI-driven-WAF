"""
Integration and behavior tests for FastAPI WAF Gateway (Task 3).
Tests:
  - Header / query / body forwarding
  - Hop-by-hop header stripping
  - Blocked verdict returns HTTP 403
  - Monitor mode allows traffic through
  - Sensitive value masking
  - Resilient async logging when DB is unavailable
  - Fail-mode behavior (open vs closed)
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient

from gateway.config import settings
from gateway.main import app, log_queue
from gateway.models import Event, get_db
from gateway.pipeline import RuleResult, Verdict


@pytest.fixture(scope="module")
def client():
    # Use TestClient with lifespan across module
    with TestClient(app, base_url="http://testserver") as test_client:
        yield test_client


def test_healthz_endpoint(client):
    """Verify /healthz returns 200 OK and is not intercepted as proxy traffic."""
    resp = client.get("/healthz")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["service"] == "waf-gateway"


def test_forwarding_headers_query_and_body(client):
    """Verify request headers, query parameters and body are forwarded to upstream with WAF headers added."""
    mock_upstream_response = httpx.Response(
        status_code=200,
        headers={"Content-Type": "application/json", "X-Server": "UpstreamDemo"},
        stream=httpx.ByteStream(b'{"result": "success"}'),
    )

    with patch("gateway.main.http_client.send", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = mock_upstream_response

        resp = client.post(
            "/api/submit?item=book&sort=desc",
            headers={
                "User-Agent": "TestClient/1.0",
                "Connection": "keep-alive",  # hop-by-hop
                "Custom-Header": "AllowedVal",
            },
            json={"title": "Clean Input"},
        )

        assert resp.status_code == 200
        assert resp.json() == {"result": "success"}
        assert "x-waf-request-id" in resp.headers
        assert resp.headers["x-waf-verdict"] == "allow"

        # Verify call to upstream
        assert mock_send.call_count == 1
        fwd_req = mock_send.call_args[0][0]
        assert str(fwd_req.url).endswith("/api/submit?item=book&sort=desc")
        assert fwd_req.headers["custom-header"] == "AllowedVal"
        assert "connection" not in fwd_req.headers  # Hop-by-hop stripped
        assert "x-forwarded-for" in fwd_req.headers
        assert "x-waf-request-id" in fwd_req.headers


def test_blocked_verdict_returns_403(client):
    """Verify that a blocked request returns HTTP 403 without contacting upstream."""
    mock_blocked_verdict = Verdict(
        action="block",
        attack_type="sqli",
        rule_hit="SQLI-001",
        ml_score=0.98,
        explanation={"matched_rule": "SQLI-001"},
    )

    with patch("gateway.main.decide", return_value=mock_blocked_verdict), patch(
        "gateway.main.http_client.send", new_callable=AsyncMock
    ) as mock_send:
        resp = client.get("/search?q=' OR '1'='1")

        assert resp.status_code == 403
        assert "403 Forbidden" in resp.text
        assert "Request ID:" in resp.text
        assert resp.headers["x-waf-verdict"] == "block"
        # Upstream must not be contacted
        mock_send.assert_not_called()


def test_monitor_mode_flags_without_blocking(client):
    """Verify that in monitor mode, threats are marked 'flag' and forwarded to upstream."""
    mock_flagged_verdict = Verdict(
        action="flag",
        attack_type="xss",
        rule_hit="XSS-001",
        ml_score=0.88,
        explanation={"matched_rule": "XSS-001"},
    )
    mock_upstream_response = httpx.Response(
        status_code=200,
        stream=httpx.ByteStream(b"Allowed in monitor mode"),
    )

    with patch("gateway.main.decide", return_value=mock_flagged_verdict), patch(
        "gateway.main.http_client.send", new_callable=AsyncMock
    ) as mock_send:
        mock_send.return_value = mock_upstream_response

        resp = client.get("/search?q=<script>alert(1)</script>")
        assert resp.status_code == 200
        assert resp.headers["x-waf-verdict"] == "flag"
        mock_send.assert_called_once()


def test_sensitive_parameters_masked_in_logs():
    """Verify password, token, and secret values are masked before event queue."""
    from gateway.masking import mask_body_summary, mask_query_string

    raw_query = "user=alice&password=SuperSecretPassword123!&token=jwt_xyz"
    masked_q = mask_query_string(raw_query)
    assert "password=%5BREDACTED%5D" in masked_q or "password=[REDACTED]" in masked_q
    assert "SuperSecretPassword123" not in masked_q

    raw_json_body = '{"username": "admin", "password": "MySecretPassword", "nested": {"api_key": "key-999"}}'
    masked_body = mask_body_summary(raw_json_body)
    assert '"password": "[REDACTED]"' in masked_body
    assert "MySecretPassword" not in masked_body


def test_gateway_resilience_when_db_down(client):
    """Verify that if the DB persistence raises an exception, the gateway does not fail requests."""
    mock_upstream_response = httpx.Response(
        status_code=200,
        stream=httpx.ByteStream(b"All good"),
    )

    with patch("gateway.main.http_client.send", new_callable=AsyncMock) as mock_send, patch(
        "gateway.main._write_event_sync", side_effect=Exception("Database connection timeout")
    ):
        mock_send.return_value = mock_upstream_response
        resp = client.get("/catalog")
        assert resp.status_code == 200
        assert resp.text == "All good"


def test_fail_mode_open_vs_closed(client):
    """Verify FAIL_MODE configuration determines behavior on unhandled inspection error."""
    # Test FAIL_MODE = closed (default) -> returns 403
    with patch("gateway.main.normalise_request", side_effect=RuntimeError("Parsing crash")), patch(
        "gateway.main.settings.fail_mode", "closed"
    ):
        resp = client.get("/crash-test")
        assert resp.status_code == 403
        assert "403 Forbidden" in resp.text

    # Test FAIL_MODE = open -> allows request through
    mock_upstream_response = httpx.Response(
        status_code=200,
        stream=httpx.ByteStream(b"Allowed open"),
    )
    with patch("gateway.main.normalise_request", side_effect=RuntimeError("Parsing crash")), patch(
        "gateway.main.settings.fail_mode", "open"
    ), patch("gateway.main.http_client.send", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = mock_upstream_response
        resp = client.get("/crash-test-open")
        assert resp.status_code == 200
        assert resp.text == "Allowed open"
