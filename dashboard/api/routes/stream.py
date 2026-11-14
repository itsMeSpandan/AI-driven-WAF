"""
Server-Sent Events (SSE) live alert stream endpoint.
Streams real-time WAF telemetry to the analytics dashboard.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

from gateway.models import Event, get_engine
from sqlalchemy.orm import sessionmaker

router = APIRouter(prefix="/api", tags=["stream"])


@router.get("/stream")
async def sse_event_stream(request: Request):
    """
    Server-Sent Events endpoint emitting live alerts and events.
    Dashboard UI subscribes to this for real-time live alert feed.
    """
    engine = get_engine()
    SessionLocal = sessionmaker(bind=engine)

    async def event_generator():
        # Keep track of last queried timestamp
        last_seen = datetime.now(timezone.utc) - timedelta(seconds=10)

        # Send initial connection confirmation
        yield ": connected to waf-sse\n\n"

        while True:
            # Check client disconnection
            if await request.is_disconnected():
                break

            try:
                with SessionLocal() as db:
                    new_events = (
                        db.query(Event)
                        .filter(Event.ts > last_seen)
                        .order_by(Event.ts.asc())
                        .limit(20)
                        .all()
                    )

                    if new_events:
                        for ev in new_events:
                            last_seen = max(last_seen, ev.ts)
                            data = {
                                "id": ev.id,
                                "ts": ev.ts.isoformat(),
                                "client_ip": ev.client_ip,
                                "method": ev.method,
                                "path": ev.path,
                                "verdict": ev.verdict,
                                "attack_type": ev.attack_type,
                                "ml_score": ev.ml_score,
                                "rule_hit": ev.rule_hit,
                                "latency_ms": ev.latency_ms,
                            }
                            yield f"event: alert\ndata: {json.dumps(data)}\n\n"
                    else:
                        # Send periodic heartbeat keepalive comment
                        yield ": ping\n\n"

            except Exception as err:
                yield f": error checking events: {err}\n\n"

            await asyncio.sleep(2.0)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
