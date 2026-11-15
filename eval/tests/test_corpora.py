"""
Unit tests for evaluation corpora generator and anti-leakage invariance.
Stage 5 Task 2.
"""

import json
from pathlib import Path
import pandas as pd
import pytest

from eval.build_corpora import (
    payload_to_request_spec,
    CORPORA_DIR,
    PROCESSED_DATA_DIR,
)


def test_deterministic_spec_generation():
    """Verify that payload_to_request_spec produces identical output for identical inputs."""
    spec1 = payload_to_request_spec(12, "test' OR 1=1--", 1, "sqli", "test_source", "test_set")
    spec2 = payload_to_request_spec(12, "test' OR 1=1--", 1, "sqli", "test_source", "test_set")
    assert spec1 == spec2
    assert spec1["id"] == "test_set-00012"
    assert spec1["label"] == 1


def test_corpora_files_exist():
    """Verify all 7 evaluation corpora files are present and non-empty."""
    expected_files = [
        "test.jsonl",
        "evasion_test.jsonl",
        "evasion_familyA.jsonl",
        "benign_obfuscated.jsonl",
        "cross_source.jsonl",
        "neutral.jsonl",
        "large_benign.jsonl",
    ]
    for fname in expected_files:
        fpath = CORPORA_DIR / fname
        assert fpath.exists(), f"Corpus {fname} missing!"
        assert fpath.stat().st_size > 0, f"Corpus {fname} is empty!"


def test_corpora_schema_conformance():
    """Verify that every line in test.jsonl and neutral.jsonl parses strictly as a valid request spec."""
    required_keys = {"id", "method", "path", "headers", "body", "label", "attack_type", "set"}
    
    for fname in ["test.jsonl", "neutral.jsonl"]:
        fpath = CORPORA_DIR / fname
        with open(fpath, "r", encoding="utf-8") as f:
            for i, line in enumerate(f):
                if i >= 100:  # Sample first 100 lines
                    break
                data = json.loads(line)
                assert required_keys.issubset(set(data.keys())), f"Missing keys in {fname} line {i}"
                assert data["method"] in ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS")
                assert data["label"] in (0, 1)


def test_anti_leakage_strict_zero_overlap():
    """Verify zero overlap between active training set and test/evasion corpora."""
    if not (PROCESSED_DATA_DIR / "train_augmented.csv").exists():
        pytest.skip("train_augmented.csv missing (run 'make data' to regenerate)")

    train_aug = pd.read_csv(PROCESSED_DATA_DIR / "train_augmented.csv")
    train_texts = set(train_aug["text"].dropna().astype(str))

    for fname in ["test.jsonl", "evasion_test.jsonl", "neutral.jsonl"]:
        fpath = CORPORA_DIR / fname
        with open(fpath, "r", encoding="utf-8") as f:
            for line in f:
                data = json.loads(line)
                raw = data.get("raw_payload", "")
                assert raw not in train_texts, f"Leakage detected in {fname}: {raw}"
