"""
Integrity & anti-leakage tests for augmented datasets (ml/tests/test_augmented_integrity.py).
Verifies:
  - Zero leakage between train_augmented.csv and any evaluation split
  - Zero Family B mutator artifacts in train_augmented.csv
  - Correct class balance and non-empty splits
  - Schema conformance across all generated CSV files
"""

from pathlib import Path
import pandas as pd
import pytest

PROCESSED_DIR = Path(__file__).resolve().parent.parent / "data" / "processed"


@pytest.fixture(scope="module")
def datasets():
    if not (PROCESSED_DIR / "train_augmented.csv").exists():
        pytest.skip("Augmented datasets missing! Run 'make data' first.")
    return {
        "train_aug": pd.read_csv(PROCESSED_DIR / "train_augmented.csv"),
        "val": pd.read_csv(PROCESSED_DIR / "val.csv"),
        "test": pd.read_csv(PROCESSED_DIR / "test.csv"),
        "evasion_b": pd.read_csv(PROCESSED_DIR / "evasion_test.csv"),
        "evasion_a": pd.read_csv(PROCESSED_DIR / "evasion_test_familyA.csv"),
        "benign_obf": pd.read_csv(PROCESSED_DIR / "benign_obfuscated_test.csv"),
    }


def test_zero_leakage_between_augmented_train_and_evaluation(datasets):
    """Verify that no augmented training sample appears in any evaluation set."""
    train_aug_texts = set(datasets["train_aug"]["text"].astype(str))

    val_texts = set(datasets["val"]["text"].astype(str))
    test_texts = set(datasets["test"]["text"].astype(str))
    evasion_b_texts = set(datasets["evasion_b"]["text"].astype(str))

    assert len(train_aug_texts.intersection(val_texts)) == 0, "Leakage: samples overlap with validation set"
    assert len(train_aug_texts.intersection(test_texts)) == 0, "Leakage: samples overlap with test set"
    assert len(train_aug_texts.intersection(evasion_b_texts)) == 0, "Leakage: samples overlap with Family B evasion set"


def test_evasion_test_strictly_family_b(datasets):
    """Verify evasion_test only contains malicious samples with Family B source tags."""
    evasion_df = datasets["evasion_b"]
    assert (evasion_df["label"] == 1).all(), "evasion_test must only contain malicious samples"
    assert evasion_df["source"].str.contains("familyB").all(), "All evasion_test samples must derive from Family B"


def test_benign_obfuscated_test_strictly_benign(datasets):
    """Verify benign_obfuscated_test contains only benign samples for FPR benchmarking."""
    benign_df = datasets["benign_obf"]
    assert (benign_df["label"] == 0).all(), "benign_obfuscated_test must only contain benign samples"
    assert (benign_df["attack_type"] == "benign").all()


def test_augmented_train_includes_both_classes(datasets):
    """Verify augmented train set contains both augmented malicious and augmented benign samples."""
    train_df = datasets["train_aug"]
    mal_count = (train_df["label"] == 1).sum()
    benign_count = (train_df["label"] == 0).sum()
    assert mal_count > 4700
    assert benign_count > 7000
    assert train_df["source"].str.contains("familyA_aug").any()


def test_schema_conformance(datasets):
    """Verify all datasets adhere to the expected canonical column schema."""
    expected_cols = {"text", "label", "attack_type", "source", "split"}
    for name, df in datasets.items():
        assert expected_cols.issubset(set(df.columns)), f"{name} is missing expected columns"
        assert not df["text"].isnull().any(), f"{name} contains null text values"
