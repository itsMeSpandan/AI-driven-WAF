"""
Analyst feedback export endpoint.
Implements Stage 4 Task 3 per TRD 2.6:
  - GET /api/feedback/export (admin only)
  - Exports labeled dataset of canonical texts, labels, and metadata for safe retraining
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from dashboard.api.auth import get_current_admin
from dashboard.api.schemas import FeedbackExportItem, FeedbackExportResponse
from gateway.models import Feedback, get_db

router = APIRouter(prefix="/api/feedback", tags=["feedback"])


@router.get("/export", response_model=FeedbackExportResponse)
def export_feedback(
    limit: int = Query(500, ge=1, le=5000),
    db: Session = Depends(get_db),
    admin: dict = Depends(get_current_admin),
):
    """
    Export analyst-verified feedback instances for model retraining.
    Returns canonical text representation and validated labels.
    """
    rows = db.query(Feedback).order_by(Feedback.ts.desc()).limit(limit).all()
    total = db.query(Feedback).count()

    items = [
        FeedbackExportItem(
            id=r.id,
            event_id=r.event_id,
            ts=r.ts,
            analyst=r.analyst,
            label=r.label,
            notes=r.notes,
            model_version=r.model_version,
            canonical_text=r.canonical_text,
        )
        for r in rows
    ]

    return FeedbackExportResponse(total=total, items=items)
