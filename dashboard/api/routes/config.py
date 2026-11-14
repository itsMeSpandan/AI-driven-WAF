"""
WAF dynamic configuration endpoints.
"""

from __future__ import annotations

import os
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from dashboard.api.schemas import WAFConfig
from gateway.models import Config, get_db

router = APIRouter(prefix="/api/config", tags=["config"])


@router.get("", response_model=WAFConfig)
def get_config(db: Session = Depends(get_db)):
    configs = {c.key: c.value for c in db.query(Config).all()}

    return WAFConfig(
        waf_mode=configs.get("waf_mode", os.getenv("WAF_MODE", "block")),
        ml_threshold=float(configs.get("ml_threshold", os.getenv("ML_THRESHOLD", "0.75"))),
        max_body_inspect_bytes=int(
            configs.get("max_body_inspect_bytes", os.getenv("MAX_BODY_INSPECT_BYTES", "16384"))
        ),
        fail_mode=configs.get("fail_mode", os.getenv("FAIL_MODE", "closed")),
    )


@router.put("", response_model=WAFConfig)
def update_config(payload: WAFConfig, db: Session = Depends(get_db)):
    config_dict = {
        "waf_mode": payload.waf_mode,
        "ml_threshold": str(payload.ml_threshold),
        "max_body_inspect_bytes": str(payload.max_body_inspect_bytes),
        "fail_mode": payload.fail_mode,
    }

    for k, v in config_dict.items():
        entry = db.query(Config).filter(Config.key == k).first()
        if entry:
            entry.value = v
        else:
            db.add(Config(key=k, value=v))

    db.commit()

    return payload
