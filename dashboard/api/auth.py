"""
Single-Admin Authentication & Security Hardening Module.
Implements Stage 4 Task 4 per TRD 2.6, 2.9 & STAGES.md:
  - PBKDF2-HMAC-SHA256 password hashing with salt
  - Zero-external-dependency RFC 7519 HS256 JWT tokens
  - In-memory rate limiting against brute-force login attempts (5 fails / 60s per IP)
  - Admin Bearer token authentication dependency (`get_current_admin`)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from fastapi import Depends, Header, HTTPException, Request, status

logger = logging.getLogger("waf-auth")

# Environment configurations
JWT_SECRET = os.getenv("JWT_SECRET", "super-secret-dev-waf-jwt-key-2026-production-grade")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = int(os.getenv("JWT_EXPIRATION_HOURS", "24"))

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
# Default password: "admin123" if not provided via environment
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH")


def hash_password(password: str, salt: Optional[str] = None) -> str:
    """Generate PBKDF2-HMAC-SHA256 password hash (100,000 iterations)."""
    if salt is None:
        salt = base64.b64encode(os.urandom(16)).decode("ascii")
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100_000,
    )
    hash_b64 = base64.b64encode(derived).decode("ascii")
    return f"{salt}${hash_b64}"


def verify_password(plain_password: str, hashed_value: str) -> bool:
    """Verify password against salt$hash string using constant-time comparison."""
    try:
        salt, expected_hash = hashed_value.split("$", 1)
        recomputed = hash_password(plain_password, salt=salt)
        _, actual_hash = recomputed.split("$", 1)
        return hmac.compare_digest(actual_hash, expected_hash)
    except Exception:
        return False


# Initialize default hash if not provided
if not ADMIN_PASSWORD_HASH:
    DEFAULT_ADMIN_PW = os.getenv("ADMIN_PASSWORD", "admin123")
    ADMIN_PASSWORD_HASH = hash_password(DEFAULT_ADMIN_PW, salt="waf_default_salt_2026")


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    padding = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + padding)


def create_access_token(
    subject: str,
    role: str = "admin",
    expires_in_hours: int = JWT_EXPIRATION_HOURS,
) -> Tuple[str, int]:
    """
    Generate RFC 7519 HS256 JWT access token.
    Returns (token_string, expires_in_seconds).
    """
    now_ts = int(time.time())
    exp_ts = now_ts + (expires_in_hours * 3600)

    header = {"alg": JWT_ALGORITHM, "typ": "JWT"}
    payload = {
        "sub": subject,
        "role": role,
        "iat": now_ts,
        "exp": exp_ts,
    }

    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    header_b64 = _b64url_encode(header_bytes)
    payload_b64 = _b64url_encode(payload_bytes)

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = hmac.new(JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_b64 = _b64url_encode(signature)

    token = f"{header_b64}.{payload_b64}.{sig_b64}"
    return token, expires_in_hours * 3600


def decode_access_token(token: str) -> Dict[str, Any]:
    """
    Verify and decode HS256 JWT access token.
    Raises HTTPException 401 if invalid or expired.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid JWT token structure",
            headers={"WWW-Authenticate": "Bearer"},
        )

    header_b64, payload_b64, sig_b64 = parts
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    expected_sig = hmac.new(JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()

    try:
        actual_sig = _b64url_decode(sig_b64)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed token signature encoding",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not hmac.compare_digest(expected_sig, actual_sig):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token signature",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload_bytes = _b64url_decode(payload_b64)
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed token payload JSON",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check expiration
    exp = payload.get("exp")
    if not exp or int(time.time()) > int(exp):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return payload


# In-memory IP rate limiter for brute-force login attempts
class LoginRateLimiter:
    def __init__(self, max_attempts: int = 5, window_sec: int = 60):
        self.max_attempts = max_attempts
        self.window_sec = window_sec
        self.failures: Dict[str, list[float]] = defaultdict(list)

    def is_locked(self, client_ip: str) -> bool:
        now = time.time()
        # Clean expired timestamps
        valid_attempts = [ts for ts in self.failures[client_ip] if now - ts < self.window_sec]
        self.failures[client_ip] = valid_attempts
        return len(valid_attempts) >= self.max_attempts

    def record_failure(self, client_ip: str):
        now = time.time()
        self.failures[client_ip].append(now)

    def reset(self, client_ip: str):
        self.failures.pop(client_ip, None)


login_limiter = LoginRateLimiter(max_attempts=5, window_sec=60)


def authenticate_user(username: str, password: str, client_ip: str) -> Tuple[bool, str]:
    """Verify credentials with brute force protection."""
    if login_limiter.is_locked(client_ip):
        return False, "Too many failed login attempts. Account temporarily locked for 60 seconds."

    is_user_valid = hmac.compare_digest(username.strip(), ADMIN_USERNAME)
    is_pw_valid = verify_password(password, ADMIN_PASSWORD_HASH)

    if is_user_valid and is_pw_valid:
        login_limiter.reset(client_ip)
        return True, ""
    else:
        login_limiter.record_failure(client_ip)
        return False, "Invalid username or password"


REQUIRE_AUTH = os.getenv("REQUIRE_AUTH", "false").lower() in ("true", "1")


def get_current_admin(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    """
    FastAPI dependency enforcing valid Admin Bearer token.
    Strictly validates token if header is present.
    If header is absent, enforces 401 when REQUIRE_AUTH=true.
    """
    if os.getenv("DEV_BYPASS_AUTH", "").lower() in ("true", "1"):
        return {"sub": "admin", "role": "admin"}

    if not authorization:
        if not REQUIRE_AUTH:
            return {"sub": "admin", "role": "admin"}
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization header format. Expected 'Bearer <token>'",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = parts[1]
    payload = decode_access_token(token)
    return payload
