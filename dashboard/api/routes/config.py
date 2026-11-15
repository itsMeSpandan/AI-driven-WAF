"""
WAF dynamic configuration and audit trail endpoints.
Implements Stage 4 Task 1:
  - Runtime settings query and update with strict Pydantic validation
  - Audit trail logging (ConfigAudit) of every setting change
  - Threshold sweep trade-off curve endpoint for interactive UI slider
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from dashboard.api.auth import get_current_admin
from dashboard.api.schemas import (
    ConfigAuditItem,
    ConfigAuditResponse,
    ThresholdSweepPoint,
    ThresholdSweepResponse,
    WAFConfig,
)
from gateway.models import Config, ConfigAudit, get_db

router = APIRouter(prefix="/api/config", tags=["config"])
REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
METADATA_PATH = REPO_ROOT / "ml" / "models" / "metadata.json"


@router.get("", response_model=WAFConfig)
def get_config(db: Session = Depends(get_db)):
    configs = {c.key: c.value for c in db.query(Config).all()}

    return WAFConfig(
        waf_mode=configs.get("waf_mode", os.getenv("WAF_MODE", "block")),
        ml_threshold=float(configs.get("ml_threshold", os.getenv("ML_THRESHOLD", "0.94"))),
        max_body_inspect_bytes=int(
            configs.get("max_body_inspect_bytes", os.getenv("MAX_BODY_INSPECT_BYTES", "16384"))
        ),
        fail_mode=configs.get("fail_mode", os.getenv("FAIL_MODE", "closed")),
        rate_limit_enabled=configs.get("rate_limit_enabled", "true").lower() in ("true", "1", "yes"),
        rate_limit_window_sec=int(configs.get("rate_limit_window_sec", "10")),
        rate_limit_burst=int(configs.get("rate_limit_burst", "30")),
        rate_enforce=configs.get("rate_enforce", "false").lower() in ("true", "1", "yes"),
    )


@router.put("", response_model=WAFConfig)
def update_config(
    payload: WAFConfig,
    db: Session = Depends(get_db),
    admin: dict = Depends(get_current_admin),
):
    config_dict = {
        "waf_mode": payload.waf_mode,
        "ml_threshold": str(payload.ml_threshold),
        "max_body_inspect_bytes": str(payload.max_body_inspect_bytes),
        "fail_mode": payload.fail_mode,
        "rate_limit_enabled": "true" if payload.rate_limit_enabled else "false",
        "rate_limit_window_sec": str(payload.rate_limit_window_sec),
        "rate_limit_burst": str(payload.rate_limit_burst),
        "rate_enforce": "true" if payload.rate_enforce else "false",
    }

    actor = admin.get("sub", "admin")

    for k, new_val in config_dict.items():
        entry = db.query(Config).filter(Config.key == k).first()
        old_val = entry.value if entry else None

        if entry:
            if entry.value != new_val:
                entry.value = new_val
                db.add(ConfigAudit(actor=actor, key=k, old_value=old_val, new_value=new_val))
        else:
            db.add(Config(key=k, value=new_val))
            db.add(ConfigAudit(actor=actor, key=k, old_value=None, new_value=new_val))

    db.commit()
    return payload


@router.get("/audit", response_model=ConfigAuditResponse)
def get_config_audit(
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    """Retrieve the recent configuration audit trail entries."""
    rows = (
        db.query(ConfigAudit)
        .order_by(ConfigAudit.ts.desc())
        .limit(limit)
        .all()
    )
    total = db.query(ConfigAudit).count()

    items = [
        ConfigAuditItem(
            id=r.id,
            ts=r.ts,
            actor=r.actor,
            key=r.key,
            old_value=r.old_value,
            new_value=r.new_value,
        )
        for r in rows
    ]
    return ConfigAuditResponse(total=total, items=items)


@router.get("/threshold-sweep", response_model=ThresholdSweepResponse)
def get_threshold_sweep(db: Session = Depends(get_db)):
    """
    Returns empirical FPR vs Recall validation trade-off curve
    so the Settings UI threshold slider can display real-time impact.
    """
    sweep_points: List[ThresholdSweepPoint] = []
    active_th = 0.94

    if METADATA_PATH.exists():
        try:
            with open(METADATA_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                active_th = float(data.get("threshold", 0.94))
                raw_sweep = data.get("threshold_sweep", [])
                sweep_points = [
                    ThresholdSweepPoint(
                        threshold=p["threshold"],
                        fpr=p["fpr"],
                        recall=p["recall"],
                        f1=p["f1"],
                    )
                    for p in raw_sweep
                ]
        except Exception:
            pass

    # Read active threshold from DB if customized
    entry = db.query(Config).filter(Config.key == "ml_threshold").first()
    if entry:
        try:
            active_th = float(entry.value)
        except ValueError:
            pass

    return ThresholdSweepResponse(
        active_threshold=active_th,
        suggested_threshold=0.94,
        points=sweep_points,
    )
