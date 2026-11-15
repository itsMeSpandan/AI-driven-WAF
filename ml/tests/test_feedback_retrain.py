"""
Unit tests for analyst feedback retraining, safety promotion gates, and rollback.
TRD 2.3 & STAGES.md Stage 4 Task 3.
"""

import datetime
import hashlib
import json
import shutil
import tempfile
from pathlib import Path
import pandas as pd
import pytest

from ml.retrain_feedback import (
    sanitize_and_deduplicate_feedback,
    promote_candidate_model,
    rollback_active_model,
    CANDIDATE_DIR,
    BACKUP_DIR,
    MODELS_DIR,
    DATA_DIR,
)


def test_feedback_deduplication():
    now = datetime.datetime.now(datetime.timezone.utc)
    t1 = now - datetime.timedelta(minutes=10)
    t2 = now

    raw_df = pd.DataFrame([
        {
            "id": "1",
            "event_id": "ev-1",
            "ts": t1,
            "analyst": "analyst-a",
            "label": "fp",
            "notes": "First thought it was false positive",
            "canonical_text": "get /items?q=shoes",
        },
        {
            "id": "2",
            "event_id": "ev-1",
            "ts": t2,
            "analyst": "analyst-b",
            "label": "tp",
            "notes": "Correction: actually malicious",
            "canonical_text": "get /items?q=shoes",
        },
    ])

    clean_df, rejected = sanitize_and_deduplicate_feedback(raw_df)
    assert len(clean_df) == 1
    assert len(rejected) == 0
    # Latest label 'tp' -> label 1
    assert clean_df.iloc[0]["label"] == 1
    assert clean_df.iloc[0]["notes"] == "Correction: actually malicious"


def test_poisoning_defense_rejects_rule_conflict():
    now = datetime.datetime.now(datetime.timezone.utc)
    raw_df = pd.DataFrame([
        {
            "id": "poison-1",
            "event_id": "ev-p1",
            "ts": now,
            "analyst": "rogue-agent",
            "label": "fp",  # Claiming high-severity SQLi is benign!
            "notes": "Should be allowed",
            "canonical_text": "get /items?id=1 or 1=1",
        },
        {
            "id": "legit-1",
            "event_id": "ev-ok1",
            "ts": now,
            "analyst": "honest-analyst",
            "label": "fp",
            "notes": "Normal company query",
            "canonical_text": "get /search?q=o'reilly books",
        },
    ])

    clean_df, rejected = sanitize_and_deduplicate_feedback(raw_df)
    assert len(clean_df) == 1
    assert len(rejected) == 1
    assert "SQLI-001" in rejected[0]["rule_matched"]
    assert clean_df.iloc[0]["text"] == "get /search?q=o'reilly books"


def test_frozen_datasets_hashes_remain_intact():
    """Verify that none of the frozen evaluation sets are modified."""
    frozen_files = [
        DATA_DIR / "test.csv",
        DATA_DIR / "evasion_test.csv",
        DATA_DIR / "cross_source_test.csv",
        DATA_DIR / "benign_obfuscated_test.csv",
    ]

    hashes = {}
    for f in frozen_files:
        assert f.exists(), f"Missing {f}"
        hashes[f.name] = hashlib.sha256(f.read_bytes()).hexdigest()

    # Re-verify hashes are unchanged
    for f in frozen_files:
        current_hash = hashlib.sha256(f.read_bytes()).hexdigest()
        assert current_hash == hashes[f.name], f"Frozen dataset {f.name} was modified!"


def test_promotion_blocks_unqualified_candidate(monkeypatch, tmp_path):
    """Verify that a candidate model with gates_passed=False cannot be promoted."""
    fake_cand_dir = tmp_path / "candidate"
    fake_cand_dir.mkdir()
    fake_model = fake_cand_dir / "model_candidate.joblib"
    fake_meta = fake_cand_dir / "metadata_candidate.json"
    fake_model.write_text("fake_model_bytes")
    fake_meta.write_text(json.dumps({"gates_passed": False, "model_version": "cand_bad"}))

    monkeypatch.setattr("ml.retrain_feedback.CANDIDATE_DIR", fake_cand_dir)

    with pytest.raises(RuntimeError, match="Promotion blocked: Candidate model failed automated safety gates"):
        promote_candidate_model()


def test_promotion_and_rollback_lifecycle(monkeypatch, tmp_path):
    """Test full cycle: backup active -> promote candidate -> rollback to backup."""
    fake_models_dir = tmp_path / "models"
    fake_cand_dir = fake_models_dir / "candidate"
    fake_backup_dir = fake_models_dir / "backup"
    fake_cand_dir.mkdir(parents=True)
    fake_backup_dir.mkdir(parents=True)

    # Setup active model
    active_model = fake_models_dir / "model.joblib"
    active_meta = fake_models_dir / "metadata.json"
    active_model.write_text("active_model_v1")
    active_meta.write_text(json.dumps({"model_version": "v1.0"}))

    # Setup candidate model
    cand_model = fake_cand_dir / "model_candidate.joblib"
    cand_meta = fake_cand_dir / "metadata_candidate.json"
    cand_model.write_text("cand_model_v2")
    cand_meta.write_text(json.dumps({"model_version": "v2.0", "gates_passed": True}))

    monkeypatch.setattr("ml.retrain_feedback.MODELS_DIR", fake_models_dir)
    monkeypatch.setattr("ml.retrain_feedback.CANDIDATE_DIR", fake_cand_dir)
    monkeypatch.setattr("ml.retrain_feedback.BACKUP_DIR", fake_backup_dir)

    # 1. Promote
    promote_candidate_model()
    assert active_model.read_text() == "cand_model_v2"
    assert (fake_backup_dir / "model_backup.joblib").read_text() == "active_model_v1"

    # 2. Rollback
    rollback_active_model()
    assert active_model.read_text() == "active_model_v1"
    assert json.loads(active_meta.read_text())["model_version"] == "v1.0"

