"""
Database models and connection handling.
Implements the exact schema from TRD 2.7:
  - events
  - config
  - model_versions
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Generator, Optional

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
    create_engine,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    pass


class Event(Base):
    """Logs every HTTP inspection decision made by the WAF gateway."""

    __tablename__ = "events"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    ts = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    client_ip = Column(String(64), nullable=False, default="unknown")
    method = Column(String(16), nullable=False)
    path = Column(Text, nullable=False)
    query_summary = Column(Text, default="")
    body_summary = Column(Text, default="")
    user_agent = Column(Text, default="")
    rule_hit = Column(String(128), nullable=True)
    ml_score = Column(Float, default=0.0, nullable=False)
    verdict = Column(String(16), nullable=False)  # 'allow', 'flag', 'block'
    attack_type = Column(String(64), default="benign", nullable=False)
    latency_ms = Column(Float, default=0.0, nullable=False)
    explanation = Column(JSON, default=dict)
    feedback = Column(String(16), nullable=True)  # 'fp', 'tp', None
    model_version = Column(String(64), default="none", nullable=True)
    anomaly_flag = Column(String(64), nullable=True)  # 'rate_burst', 'block_burst', 'scanner_like'

    __table_args__ = (
        Index("idx_events_ts", "ts"),
        Index("idx_events_verdict", "verdict"),
        Index("idx_events_attack_type", "attack_type"),
        Index("idx_events_path", "path"),
        Index("idx_events_anomaly_flag", "anomaly_flag"),
    )


class Config(Base):
    """Runtime dynamic WAF configurations (mode, threshold, rate limits)."""

    __tablename__ = "config"

    key = Column(String(128), primary_key=True)
    value = Column(Text, nullable=False)


class ConfigAudit(Base):
    """Audit trail of runtime configuration changes."""

    __tablename__ = "config_audit"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ts = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    actor = Column(String(64), default="admin", nullable=False)
    key = Column(String(128), nullable=False)
    old_value = Column(Text, nullable=True)
    new_value = Column(Text, nullable=True)

    __table_args__ = (
        Index("idx_config_audit_ts", "ts"),
    )


class Feedback(Base):
    """Analyst false positive / true positive reviews for model calibration."""

    __tablename__ = "feedback"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    event_id = Column(String(36), nullable=False, index=True)
    ts = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    analyst = Column(String(64), default="admin", nullable=False)
    label = Column(String(16), nullable=False)  # 'fp', 'tp', 'clear'
    notes = Column(Text, nullable=True)
    model_version = Column(String(64), nullable=True)
    canonical_text = Column(Text, nullable=True)

    __table_args__ = (
        Index("idx_feedback_ts", "ts"),
        Index("idx_feedback_label", "label"),
    )


class ModelVersion(Base):
    """Track ML model metadata, evaluation metrics, and active model state."""

    __tablename__ = "model_versions"

    id = Column(String(64), primary_key=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    metrics = Column(JSON, default=dict)
    threshold = Column(Float, default=0.75)
    active = Column(Boolean, default=False)


# Engine and Session factory
_engine = None
_SessionFactory = None


def get_engine(db_url: Optional[str] = None):
    global _engine, _SessionFactory
    if _engine is None:
        url = db_url or os.getenv("DB_URL", "sqlite:///./data/waf.db")
        # Ensure parent directory exists for SQLite
        if url.startswith("sqlite:////"):
            db_path = url[len("sqlite:///") :]
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
        elif url.startswith("sqlite:///"):
            db_path = url[len("sqlite:///") :]
            parent = os.path.dirname(db_path)
            if parent:
                os.makedirs(parent, exist_ok=True)

        connect_args = {"check_same_thread": False, "timeout": 30.0} if "sqlite" in url else {}
        _engine = create_engine(url, connect_args=connect_args)
        _SessionFactory = sessionmaker(autocommit=False, autoflush=False, bind=_engine)
    return _engine


def init_db(db_url: Optional[str] = None):
    """Initialize database tables and set initial configuration defaults."""
    engine = get_engine(db_url)
    Base.metadata.create_all(bind=engine)

    # Lightweight migration: ensure model_version and anomaly_flag columns exist on events
    with engine.connect() as conn:
        try:
            conn.execute(text("ALTER TABLE events ADD COLUMN model_version VARCHAR(64) DEFAULT 'none'"))
            conn.commit()
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE events ADD COLUMN anomaly_flag VARCHAR(64)"))
            conn.commit()
        except Exception:
            pass

    # Populate default configurations if missing
    with sessionmaker(bind=engine)() as session:
        default_configs = {
            "waf_mode": os.getenv("WAF_MODE", "block"),
            "ml_threshold": os.getenv("ML_THRESHOLD", "0.94"),
            "max_body_inspect_bytes": os.getenv("MAX_BODY_INSPECT_BYTES", "16384"),
            "fail_mode": os.getenv("FAIL_MODE", "closed"),
            "rate_limit_enabled": "true",
            "rate_limit_window_sec": "10",
            "rate_limit_burst": "30",
            "rate_enforce": "false",
        }
        for k, v in default_configs.items():
            existing = session.query(Config).filter_by(key=k).first()
            if not existing:
                session.add(Config(key=k, value=str(v)))
        session.commit()


def get_db() -> Generator[Session, None, None]:
    get_engine()
    session = _SessionFactory()
    try:
        yield session
    finally:
        session.close()
