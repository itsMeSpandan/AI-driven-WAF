"""
Dashboard Analytics API Server.
Implements TRD 2.6 and Stage 1 Task 4 endpoints.
"""

from contextlib import asynccontextmanager
import logging
import os
import sys
from pathlib import Path

# Ensure repo root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

from dashboard.api.routes.auth import router as auth_router
from dashboard.api.routes.config import router as config_router
from dashboard.api.routes.events import router as events_router
from dashboard.api.routes.feedback import router as feedback_router
from dashboard.api.routes.stats import router as stats_router
from dashboard.api.routes.stream import router as stream_router
from gateway.models import init_db

logger = logging.getLogger("dashboard-api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    try:
        init_db()
        logger.info("Dashboard API database tables verified.")
    except Exception as e:
        logger.warning("Could not initialize DB on startup: %s", e)
    yield


app = FastAPI(
    title="AI WAF Analytics & Control API",
    description="Frozen API contract per TRD 2.6 providing telemetry, stats, SSE stream, and configuration",
    version="1.0.0",
    lifespan=lifespan,
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        try:
            response: Response = await call_next(request)
        except Exception as exc:
            logger.error("Unhandled API error on %s: %s", request.url.path, exc)
            return JSONResponse(
                status_code=500,
                content={"error": "Internal server error", "detail": "An unexpected error occurred."},
            )

        # Apply defense-in-depth security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none';"
        return response


app.add_middleware(SecurityHeadersMiddleware)


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled API exception on %s: %s", request.url.path, exc)
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "detail": "An unexpected error occurred."},
    )


# Enable CORS for Next.js dashboard UI with origin whitelist
allowed_origins_env = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000")
allowed_origins = [o.strip() for o in allowed_origins_env.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins if allowed_origins else ["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Mount API routers
app.include_router(auth_router)
app.include_router(stats_router)
app.include_router(events_router)
app.include_router(feedback_router)
app.include_router(stream_router)
app.include_router(config_router)


@app.get("/healthz", tags=["health"])
def health_check():
    return {"status": "ok", "service": "dashboard-api"}
