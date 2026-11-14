"""
Contract tests for Dashboard Analytics API (Task 4 & TRD 2.6).
Verifies all endpoints, response models, filtering, feedback updates, and SSE stream.
"""

import pytest
from fastapi.testclient import TestClient

from dashboard.api.main import app
from dashboard.api.seed_demo_data import seed_database
from gateway.models import init_db


@pytest.fixture(scope="module")
def api_client():
    # Initialize DB and seed demo data
    init_db()
    seed_database(total_events=300)
    with TestClient(app, base_url="http://testserver") as client:
        yield client


def test_stats_summary_endpoint(api_client):
    """Verify /api/stats/summary returns proper KPI metrics matching schema."""
    resp = api_client.get("/api/stats/summary?range=24h")
    assert resp.status_code == 200
    data = resp.json()

    assert "total_requests" in data
    assert "total_blocked" in data
    assert "total_flagged" in data
    assert "total_allowed" in data
    assert "block_rate" in data
    assert "avg_latency_ms" in data
    assert data["total_requests"] > 0
    assert data["total_blocked"] > 0


def test_stats_timeseries_endpoint(api_client):
    """Verify /api/stats/timeseries returns bucketed traffic vs threats points."""
    resp = api_client.get("/api/stats/timeseries?range=24h&bucket=1h")
    assert resp.status_code == 200
    data = resp.json()

    assert data["range"] == "24h"
    assert data["bucket"] == "1h"
    assert isinstance(data["points"], list)
    assert len(data["points"]) > 0

    point = data["points"][0]
    assert "timestamp" in point
    assert "total" in point
    assert "threats" in point
    assert "blocked" in point
    assert "flagged" in point


def test_stats_attack_types_endpoint(api_client):
    """Verify /api/stats/attack-types returns breakdown percentages."""
    resp = api_client.get("/api/stats/attack-types?range=24h")
    assert resp.status_code == 200
    data = resp.json()

    assert "total_attacks" in data
    assert "items" in data
    assert data["total_attacks"] > 0
    types = [item["attack_type"] for item in data["items"]]
    assert "sqli" in types
    assert "xss" in types


def test_stats_top_endpoints_endpoint(api_client):
    """Verify /api/stats/top-endpoints returns ranked targeted paths."""
    resp = api_client.get("/api/stats/top-endpoints?limit=5")
    assert resp.status_code == 200
    data = resp.json()

    assert "items" in data
    assert len(data["items"]) <= 5
    if data["items"]:
        item = data["items"][0]
        assert "path" in item
        assert "attack_count" in item
        assert "total_count" in item


def test_stats_top_ips_endpoint(api_client):
    """Verify /api/stats/top-ips returns ranked requesting IPs."""
    resp = api_client.get("/api/stats/top-ips?limit=5")
    assert resp.status_code == 200
    data = resp.json()

    assert "items" in data
    assert len(data["items"]) <= 5
    if data["items"]:
        item = data["items"][0]
        assert "ip" in item
        assert "total_requests" in item
        assert "blocked_requests" in item


def test_events_pagination_and_filtering(api_client):
    """Verify /api/events pagination and filtering by type and verdict."""
    resp = api_client.get("/api/events?limit=10&offset=0")
    assert resp.status_code == 200
    data = resp.json()

    assert "total" in data
    assert data["limit"] == 10
    assert data["offset"] == 0
    assert len(data["items"]) <= 10

    # Filter by verdict=block
    resp_blocked = api_client.get("/api/events?limit=10&verdict=block")
    assert resp_blocked.status_code == 200
    blocked_data = resp_blocked.json()
    for item in blocked_data["items"]:
        assert item["verdict"] == "block"

    # Filter by type=sqli
    resp_sqli = api_client.get("/api/events?limit=10&type=sqli")
    assert resp_sqli.status_code == 200
    sqli_data = resp_sqli.json()
    for item in sqli_data["items"]:
        assert item["attack_type"] == "sqli"


def test_event_detail_and_feedback(api_client):
    """Verify /api/events/{id} and submitting false-positive analyst feedback."""
    # Fetch an event id
    events_resp = api_client.get("/api/events?limit=1")
    event_id = events_resp.json()["items"][0]["id"]

    # Get single event detail
    detail_resp = api_client.get(f"/api/events/{event_id}")
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert detail["id"] == event_id
    assert "explanation" in detail
    assert "user_agent" in detail

    # Submit feedback 'fp'
    fb_resp = api_client.post(
        f"/api/events/{event_id}/feedback",
        json={"feedback": "fp", "notes": "Verified business parameter"},
    )
    assert fb_resp.status_code == 200
    assert fb_resp.json()["feedback"] == "fp"

    # Verify event detail now has feedback='fp'
    updated_detail = api_client.get(f"/api/events/{event_id}").json()
    assert updated_detail["feedback"] == "fp"


def test_event_detail_404_on_missing(api_client):
    """Verify 404 is returned when event ID does not exist."""
    resp = api_client.get("/api/events/non-existent-uuid-123")
    assert resp.status_code == 404


def test_config_endpoints(api_client):
    """Verify GET and PUT /api/config."""
    # Get initial config
    get_resp = api_client.get("/api/config")
    assert get_resp.status_code == 200
    init_config = get_resp.json()
    assert "waf_mode" in init_config
    assert "ml_threshold" in init_config

    # Update config
    put_resp = api_client.put(
        "/api/config",
        json={
            "waf_mode": "monitor",
            "ml_threshold": 0.85,
            "max_body_inspect_bytes": 8192,
            "fail_mode": "open",
        },
    )
    assert put_resp.status_code == 200
    updated = put_resp.json()
    assert updated["waf_mode"] == "monitor"
    assert updated["ml_threshold"] == 0.85

    # Verify updated values persist
    verify_resp = api_client.get("/api/config")
    assert verify_resp.json()["waf_mode"] == "monitor"
    assert verify_resp.json()["ml_threshold"] == 0.85


def test_sse_stream_endpoint(api_client):
    """Verify /api/stream opens a valid text/event-stream connection."""
    with api_client.stream("GET", "/api/stream") as stream_resp:
        assert stream_resp.status_code == 200
        assert "text/event-stream" in stream_resp.headers["content-type"]
        # Read first chunk
        for chunk in stream_resp.iter_lines():
            if chunk:
                assert "connected to waf-sse" in chunk or "ping" in chunk or "alert" in chunk
                break
