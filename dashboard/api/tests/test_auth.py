"""
Unit and integration tests for Authentication & Security Hardening.
TRD 2.6, 2.9 & STAGES.md Stage 4 Task 4.
"""

import time
import pytest
from fastapi.testclient import TestClient

from dashboard.api.auth import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
    login_limiter,
)
from dashboard.api.main import app
from gateway.models import init_db


@pytest.fixture(scope="module")
def client():
    init_db()
    with TestClient(app, base_url="http://testserver") as c:
        yield c


def test_password_hashing_and_verification():
    pw = "SecretP@ssw0rd!"
    hashed = hash_password(pw)
    assert verify_password(pw, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False


def test_jwt_generation_and_verification():
    token, exp = create_access_token("secops_lead", role="admin", expires_in_hours=1)
    payload = decode_access_token(token)
    assert payload["sub"] == "secops_lead"
    assert payload["role"] == "admin"
    assert payload["exp"] > int(time.time())

    # Tampered signature
    parts = token.split(".")
    tampered = f"{parts[0]}.{parts[1]}.bad_signature_here"
    with pytest.raises(Exception):
        decode_access_token(tampered)


def test_login_success_and_me_endpoint(client):
    login_limiter.reset("testclient")
    resp = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "admin123"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["username"] == "admin"

    token = data["access_token"]
    # Test GET /api/auth/me with Bearer token
    me_resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 200
    me_data = me_resp.json()
    assert me_data["username"] == "admin"
    assert me_data["authenticated"] is True


def test_login_invalid_credentials(client):
    login_limiter.reset("testclient")
    resp = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "wrong_password_99"},
    )
    assert resp.status_code == 401
    assert "Invalid username or password" in resp.json()["detail"]


def test_login_brute_force_rate_limit(client):
    login_limiter.reset("testclient")
    # Fail 5 times
    for _ in range(5):
        resp = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "bad_password"},
        )
        assert resp.status_code == 401

    # 6th attempt should be blocked with 429
    blocked_resp = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "bad_password"},
    )
    assert blocked_resp.status_code == 429
    assert "Too many failed login attempts" in blocked_resp.json()["detail"]
    login_limiter.reset("testclient")


def test_auth_header_format_validation(client):
    # Malformed header without Bearer prefix
    resp = client.get("/api/auth/me", headers={"Authorization": "Basic 12345"})
    assert resp.status_code == 401
    assert "Invalid Authorization header format" in resp.json()["detail"]

    # Invalid token string
    resp = client.get("/api/auth/me", headers={"Authorization": "Bearer not.a.valid.jwt"})
    assert resp.status_code == 401
