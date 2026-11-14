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
    String,
    Text,
    create_engine,
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

    __table_args__ = (
        Index("idx_events_ts", "ts"),
        Index("idx_events_verdict", "verdict"),
        Index("idx_events_attack_type", "attack_type"),
        Index("idx_events_path", "path"),
    )


class Config(Base):
    """Runtime dynamic WAF configurations (mode, threshold, rate limits)."""

    __tablename__ = "config"

    key = Column(String(128), primary_key=True)
    value = Column(Text, nullable=False)


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

        connect_args = {"check_same_thread": False} if "sqlite" in url else {}
        _engine = create_engine(url, connect_args=connect_args)
        _SessionFactory = sessionmaker(autocommit=False, autoflush=False, bind=_engine)
    return _engine


def init_db(db_url: Optional[str] = None):
    """Initialize database tables and set initial configuration defaults."""
    engine = get_engine(db_url)
    Base.metadata.create_all(bind=engine)

    # Populate default configurations if missing
    with sessionmaker(bind=engine)() as session:
        default_configs = {
            "waf_mode": os.getenv("WAF_MODE", "block"),
            "ml_threshold": os.getenv("ML_THRESHOLD", "0.75"),
            "max_body_inspect_bytes": os.getenv("MAX_BODY_INSPECT_BYTES", "16384"),
            "fail_mode": os.getenv("FAIL_MODE", "closed"),
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
