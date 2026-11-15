"""
Authentication routes for dashboard SecOps administration.
Implements Stage 4 Task 4 per TRD 2.6 & 2.9.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request, status

from dashboard.api.auth import (
    authenticate_user,
    create_access_token,
    get_current_admin,
)
from dashboard.api.schemas import LoginRequest, LoginResponse, UserResponse
from gateway.rate_limiter import resolve_client_ip

logger = logging.getLogger("waf-auth-route")
router = APIRouter(prefix="/api/auth", tags=["Authentication"])


@router.post("/login", response_model=LoginResponse)
async def login(payload: LoginRequest, request: Request):
    """Authenticate administrator credentials and return an RFC 7519 JWT Bearer token."""
    client_ip = resolve_client_ip(
        request.client.host if request.client else "unknown",
        request.headers.get("x-forwarded-for"),
    )
    
    success, err_msg = authenticate_user(payload.username, payload.password, client_ip)
    if not success:
        if "locked" in err_msg.lower():
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=err_msg,
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=err_msg,
            headers={"WWW-Authenticate": "Bearer"},
        )

    token, expires_in = create_access_token(payload.username.strip(), role="admin")
    logger.info("Admin login successful for '%s' from %s", payload.username, client_ip)
    return LoginResponse(
        access_token=token,
        token_type="bearer",
        expires_in_sec=expires_in,
        username=payload.username.strip(),
    )


@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(admin: Dict[str, Any] = Depends(get_current_admin)):
    """Retrieve profile and authentication state of current active session."""
    return UserResponse(
        username=admin.get("sub", "admin"),
        authenticated=True,
        role=admin.get("role", "admin"),
    )


@router.post("/logout")
async def logout():
    """Client-side token disposal endpoint."""
    return {"success": True, "message": "Logged out successfully"}
