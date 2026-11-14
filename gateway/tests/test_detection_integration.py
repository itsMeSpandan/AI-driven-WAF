"""
End-to-end integration tests for WAF detection core (Stage 2 Task 6).
Verifies:
  - Real SQLi and XSS payloads blocked (HTTP 403) in Block mode
  - Benign requests permitted through (HTTP 200)
  - Monitor mode permits threats through with HTTP 200 and 'flag' verdict
  - /healthz reports model status, version, and calibrated threshold
  - Graceful rule-only fallback when ML model is absent
"""

from unittest.mock import AsyncMock, patch
import httpx
import pytest
from fastapi.testclient import TestClient

from gateway.detector import MLDetector
from gateway.main import app
from gateway.models import init_db


@pytest.fixture(scope="module")
def client():
    init_db()
    with TestClient(app, base_url="http://testserver") as test_client:
        yield test_client


def mock_upstream_response(status_code: int = 200, text: str = "upstream-ok"):
    return httpx.Response(
        status_code=status_code,
        headers={"Content-Type": "text/plain"},
        stream=httpx.ByteStream(text.encode("utf-8")),
    )


def test_healthz_reports_ml_detector_status(client):
    """Verify /healthz exposes detector status, model version, and threshold."""
    resp = client.get("/healthz")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["service"] == "waf-gateway"
    assert "detector_status" in data
    assert "model_loaded" in data
    assert "model_version" in data
    assert "threshold" in data
    assert data["model_loaded"] is True
    assert data["detector_status"] == "active"


def test_sqli_payload_blocked_in_block_mode(client):
    """Verify classical SQLi tautology is blocked with HTTP 403 in Block mode."""
    with patch("gateway.main.get_current_mode", return_value="block"):
        resp = client.get("/items?id=1%20OR%201=1")
        assert resp.status_code == 403
        assert "403 Forbidden" in resp.text
        assert "Request ID:" in resp.text
        assert resp.headers.get("X-WAF-Verdict") == "block"
        assert resp.headers.get("X-WAF-Request-ID") is not None


def test_xss_payload_blocked_in_block_mode(client):
    """Verify XSS script payload is blocked with HTTP 403 in Block mode."""
    with patch("gateway.main.get_current_mode", return_value="block"):
        resp = client.get("/search?q=%3Cscript%3Ealert(1)%3C/script%3E")
        assert resp.status_code == 403
        assert "403 Forbidden" in resp.text
        assert resp.headers.get("X-WAF-Verdict") == "block"


def test_benign_request_allowed(client):
    """Verify standard clean web request is allowed and proxied upstream."""
    mock_resp = mock_upstream_response(200, "upstream-products-ok")
    with patch("gateway.main.get_current_mode", return_value="block"), \
         patch("gateway.main.http_client.send", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = mock_resp
        resp = client.get("/products/view?category=electronics&page=2")
        assert resp.status_code == 200
        assert "upstream-products-ok" in resp.text
        assert resp.headers.get("x-waf-verdict") == "allow"
        assert resp.headers.get("x-waf-request-id") is not None


def test_threat_in_monitor_mode_flagged_not_blocked(client):
    """Verify threats in Monitor mode are forwarded to upstream with 'flag' verdict."""
    mock_resp = mock_upstream_response(200, "upstream-search-ok")
    with patch("gateway.main.get_current_mode", return_value="monitor"), \
         patch("gateway.main.http_client.send", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = mock_resp
        resp = client.get("/search?q=1%20UNION%20SELECT%20username,%20password%20FROM%20users")
        # In monitor mode, request must reach upstream (200), not be rejected (403)
        assert resp.status_code == 200
        assert "upstream-search-ok" in resp.text
        assert resp.headers.get("x-waf-verdict") == "flag"


def test_failsafe_fallback_when_model_missing(client, tmp_path):
    """Verify gateway falls back gracefully to rule-only mode if model is missing."""
    fallback_detector = MLDetector(
        model_file=tmp_path / "non_existent_model.joblib",
        metadata_file=tmp_path / "non_existent_meta.json",
    )
    assert fallback_detector.is_loaded is False
    assert fallback_detector.model_version == "rule-only"

    mock_resp = mock_upstream_response(200, "upstream-about-ok")
    with patch("gateway.main.detector", fallback_detector), \
         patch("gateway.pipeline.detector", fallback_detector), \
         patch("gateway.main.get_current_mode", return_value="block"), \
         patch("gateway.main.http_client.send", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = mock_resp

        # Rules should still catch blatant attacks
        resp_attack = client.get("/login?user=admin'--")
        assert resp_attack.status_code == 403
        assert resp_attack.headers.get("X-WAF-Verdict") == "block"

        # Clean requests should still pass
        resp_clean = client.get("/about-us")
        assert resp_clean.status_code == 200
        assert resp_clean.headers.get("x-waf-verdict") == "allow"


def test_obfuscated_sqli_payload_blocked_with_explanation(client):
    """
    Stage 3 Task 7: Obfuscated SQLi mutation (inline comments / whitespace variants)
    is blocked in block mode and generates non-empty explanation tokens.
    """
    with patch("gateway.main.get_current_mode", return_value="block"):
        # Payload with inline comment evasion
        resp = client.get("/search?q=admin'/**/OR/**/'1'='1")
        assert resp.status_code == 403
        assert resp.headers.get("X-WAF-Verdict") == "block"
        req_id = resp.headers.get("X-WAF-Request-ID")
        assert req_id is not None

        # Verify explanation directly from pipeline for this input
        from gateway.normalizer import normalise_request
        from gateway.pipeline import rule_check, ml_score, decide
        norm = normalise_request("GET", "/search", "q=admin'/**/OR/**/'1'='1", {}, b"")
        rule = rule_check(norm)
        ml = ml_score(norm)
        verdict = decide(rule, ml, mode="block", threshold=0.94, norm=norm)

        assert verdict.action == "block"
        assert "top_tokens" in verdict.explanation
        assert len(verdict.explanation["top_tokens"]) > 0
        assert "summary" in verdict.explanation


def test_obfuscated_xss_payload_blocked_with_explanation(client):
    """
    Stage 3 Task 7: Obfuscated XSS event handler variant is blocked
    and generates non-empty explanation tokens and character offsets.
    """
    with patch("gateway.main.get_current_mode", return_value="block"):
        resp = client.get("/comments?body=%3Csvg/onload=alert(1)%3E")
        assert resp.status_code == 403
        assert resp.headers.get("X-WAF-Verdict") == "block"

        from gateway.normalizer import normalise_request
        from gateway.pipeline import rule_check, ml_score, decide
        norm = normalise_request("GET", "/comments", "body=<svg/onload=alert(1)>", {}, b"")
        rule = rule_check(norm)
        ml = ml_score(norm)
        verdict = decide(rule, ml, mode="block", threshold=0.94, norm=norm)

        assert verdict.action == "block"
        assert len(verdict.explanation["top_tokens"]) > 0
        token_info = verdict.explanation["top_tokens"][0]
        assert "start" in token_info
        assert "end" in token_info
        assert norm.canonical_text[token_info["start"]:token_info["end"]] == token_info["text"]

