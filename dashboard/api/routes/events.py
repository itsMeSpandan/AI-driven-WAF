"""
Events log, details, and false-positive feedback endpoints.
Implements Stage 4 Tasks 2, 3, 5:
  - Filtering by verdict, attack type, anomaly flag, feedback state, and text search
  - Full server-side pagination
  - Audit-grade feedback persistence with 'clear' support and canonical text tracking
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session

from dashboard.api.auth import get_current_admin
from dashboard.api.schemas import (
    EventDetailResponse,
    EventListItem,
    EventsListResponse,
    FeedbackRequest,
    FeedbackResponse,
)
from gateway.models import Event, Feedback, get_db

router = APIRouter(prefix="/api/events", tags=["events"])


@router.get("", response_model=EventsListResponse)
def list_events(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    type: Optional[str] = Query(None, description="Filter by attack_type"),
    verdict: Optional[str] = Query(None, description="Filter by verdict: allow, flag, block"),
    anomaly_flag: Optional[str] = Query(None, description="Filter by anomaly flag: rate_burst, block_burst, scanner_like"),
    feedback: Optional[str] = Query(None, description="Filter by feedback: fp, tp, unlabeled"),
    client_ip: Optional[str] = Query(None, description="Filter by client IP"),
    search: Optional[str] = Query(None, description="Free text search on path, query, or IP"),
    db: Session = Depends(get_db),
):
    query = db.query(Event)

    if type and type != "all":
        query = query.filter(Event.attack_type == type)
    if verdict and verdict != "all":
        query = query.filter(Event.verdict == verdict)
    if anomaly_flag and anomaly_flag != "all":
        query = query.filter(Event.anomaly_flag == anomaly_flag)
    if client_ip:
        query = query.filter(Event.client_ip == client_ip)

    if feedback:
        if feedback == "unlabeled":
            query = query.filter(or_(Event.feedback == None, Event.feedback == ""))
        elif feedback != "all":
            query = query.filter(Event.feedback == feedback)

    if search:
        search_pattern = f"%{search}%"
        query = query.filter(
            or_(
                Event.path.ilike(search_pattern),
                Event.query_summary.ilike(search_pattern),
                Event.client_ip.ilike(search_pattern),
            )
        )

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
            model_version=getattr(row, "model_version", "none"),
            anomaly_flag=getattr(row, "anomaly_flag", None),
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
        model_version=getattr(event, "model_version", "none"),
        anomaly_flag=getattr(event, "anomaly_flag", None),
    )


@router.post("/{event_id}/feedback", response_model=FeedbackResponse)
def submit_feedback(
    event_id: str,
    payload: FeedbackRequest,
    db: Session = Depends(get_db),
    admin: dict = Depends(get_current_admin),
):
    event = db.query(Event).filter(Event.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail=f"Event {event_id} not found")

    new_feedback = None if payload.feedback == "clear" else payload.feedback
    event.feedback = new_feedback

    # Extract canonical text for retraining
    canonical_text = ""
    if event.explanation and isinstance(event.explanation, dict):
        canonical_text = event.explanation.get("canonical_text", "")
    if not canonical_text:
        canonical_text = f"{event.method} {event.path}"
        if event.query_summary:
            canonical_text += f"?{event.query_summary}"

    feedback_record = Feedback(
        event_id=event_id,
        analyst=admin.get("sub", "admin"),
        label=payload.feedback,
        notes=payload.notes,
        model_version=getattr(event, "model_version", "none"),
        canonical_text=canonical_text,
    )
    db.add(feedback_record)
    db.commit()

    return FeedbackResponse(
        success=True,
        id=event_id,
        feedback=payload.feedback,
    )
