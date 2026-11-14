"""
Events log, details, and false-positive feedback endpoints.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from dashboard.api.schemas import (
    EventDetailResponse,
    EventListItem,
    EventsListResponse,
    FeedbackRequest,
    FeedbackResponse,
)
from gateway.models import Event, get_db

router = APIRouter(prefix="/api/events", tags=["events"])


@router.get("", response_model=EventsListResponse)
def list_events(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    type: Optional[str] = Query(None, description="Filter by attack_type"),
    verdict: Optional[str] = Query(None, description="Filter by verdict: allow, flag, block"),
    db: Session = Depends(get_db),
):
    query = db.query(Event)

    if type:
        query = query.filter(Event.attack_type == type)
    if verdict:
        query = query.filter(Event.verdict == verdict)

    total = query.count()
    rows = query.order_by(Event.ts.desc()).offset(offset).limit(limit).all()

    items = [
        EventListItem(
            id=row.id,
            ts=row.ts,
            client_ip=row.client_ip,
            method=row.method,
            path=row.path,
            query_summary=row.query_summary,
            body_summary=row.body_summary,
            verdict=row.verdict,
            attack_type=row.attack_type,
            ml_score=row.ml_score,
            rule_hit=row.rule_hit,
            latency_ms=row.latency_ms,
            feedback=row.feedback,
        )
        for row in rows
    ]

    return EventsListResponse(total=total, limit=limit, offset=offset, items=items)


@router.get("/{event_id}", response_model=EventDetailResponse)
def get_event_detail(event_id: str, db: Session = Depends(get_db)):
    event = db.query(Event).filter(Event.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail=f"Event {event_id} not found")

    return EventDetailResponse(
        id=event.id,
        ts=event.ts,
        client_ip=event.client_ip,
        method=event.method,
        path=event.path,
        query_summary=event.query_summary,
        body_summary=event.body_summary,
        user_agent=event.user_agent,
        verdict=event.verdict,
        attack_type=event.attack_type,
        ml_score=event.ml_score,
        rule_hit=event.rule_hit,
        latency_ms=event.latency_ms,
        explanation=event.explanation or {},
        feedback=event.feedback,
    )


@router.post("/{event_id}/feedback", response_model=FeedbackResponse)
def submit_feedback(
    event_id: str,
    payload: FeedbackRequest,
    db: Session = Depends(get_db),
):
    event = db.query(Event).filter(Event.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail=f"Event {event_id} not found")

    event.feedback = payload.feedback
    db.commit()

    return FeedbackResponse(
        success=True,
        id=event_id,
        feedback=payload.feedback,
    )
