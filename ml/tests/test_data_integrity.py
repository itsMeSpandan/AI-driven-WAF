"""
Unit tests covering data leakage prevention and dataset schema integrity (Task 1).
"""

from pathlib import Path
import pandas as pd
import pytest

PROCESSED_DIR = Path(__file__).resolve().parent.parent / "data" / "processed"


@pytest.fixture(scope="module")
def datasets():
    assert (PROCESSED_DIR / "train.csv").exists(), "Processed datasets missing! Run ml/prepare.py first."
    train_df = pd.read_csv(PROCESSED_DIR / "train.csv")
    val_df = pd.read_csv(PROCESSED_DIR / "val.csv")
    test_df = pd.read_csv(PROCESSED_DIR / "test.csv")
    cross_df = pd.read_csv(PROCESSED_DIR / "cross_source_test.csv")
    return train_df, val_df, test_df, cross_df


def test_zero_leakage_between_splits(datasets):
    train_df, val_df, test_df, cross_df = datasets
    train_set = set(train_df["text"].dropna())
    val_set = set(val_df["text"].dropna())
    test_set = set(test_df["text"].dropna())
    cross_set = set(cross_df["text"].dropna())

    # Verify strictly zero intersection across all evaluation partitions
    assert len(train_set & val_set) == 0, "Train and Val splits share identical samples!"
    assert len(train_set & test_set) == 0, "Train and Test splits share identical samples!"
    assert len(val_set & test_set) == 0, "Val and Test splits share identical samples!"
    assert len(train_set & cross_set) == 0, "Train and CrossSource splits share identical samples!"


def test_schema_conformance(datasets):
    required_cols = {"text", "label", "attack_type", "source", "split"}
    for df in datasets:
        assert required_cols.issubset(set(df.columns))
        assert df["label"].isin([0, 1]).all()
        assert df["text"].notnull().all()
        assert (df["text"].str.strip().str.len() > 0).all()


def test_class_distributions_present(datasets):
    train_df, _, _, _ = datasets
    attack_types = set(train_df["attack_type"].unique())
    assert "benign" in attack_types
    assert "sqli" in attack_types
    assert "xss" in attack_types
