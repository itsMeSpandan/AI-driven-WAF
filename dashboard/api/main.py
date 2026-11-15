"""
Dashboard Analytics API Server.
Implements TRD 2.6 and Stage 1 Task 4 endpoints.
"""

from contextlib import asynccontextmanager
import logging
import sys
from pathlib import Path

# Ensure repo root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

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

# Enable CORS for Next.js dashboard UI
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
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
