"""
Unit tests for the evasion mutation engine (ml/augment/mutate.py).
Tests:
  - Determinism with fixed seed
  - Semantic mutation of SQLi, XSS, and benign traffic
  - Strict isolation between Family A (training) and Family B (evaluation)
  - Non-empty output guarantees
  - Normalisation absorption measurement
"""

import pytest

from ml.augment.mutate import (
    FAMILY_A_BENIGN,
    FAMILY_A_SQLI,
    FAMILY_A_XSS,
    FAMILY_B_BENIGN,
    FAMILY_B_SQLI,
    FAMILY_B_XSS,
    measure_normalisation_absorption,
    mutate_payload,
)


def test_seed_determinism():
    """Verify that calling mutate_payload with the same seed produces identical output."""
    payload = "SELECT * FROM users WHERE id = 1 OR 1=1"
    mut1 = mutate_payload(payload, family="A", attack_type="sqli", seed=42)
    mut2 = mutate_payload(payload, family="A", attack_type="sqli", seed=42)
    assert mut1 == mut2
    assert len(mut1) > 0


def test_family_a_sqli_mutations():
    """Verify Family A SQLi mutations produce valid, non-empty variations."""
    payload = "' OR 1=1 --"
    mutations = {mutate_payload(payload, family="A", attack_type="sqli", seed=s) for s in range(20)}
    # Should produce several distinct variations
    assert len(mutations) >= 2
    for m in mutations:
        assert len(m) > 0
        # Tautology essence preserved
        assert "1" in m


def test_family_a_xss_mutations():
    """Verify Family A XSS mutations produce valid variations."""
    payload = "<script>alert(1)</script>"
    mutations = {mutate_payload(payload, family="A", attack_type="xss", seed=s) for s in range(20)}
    assert len(mutations) >= 2
    for m in mutations:
        assert len(m) > 0


def test_family_a_benign_mutations():
    """Verify benign parameter and path mutations produce safe variations."""
    payload = "category=electronics&page=2"
    mutated = mutate_payload(payload, family="A", attack_type="benign", seed=100)
    assert len(mutated) > 0
    assert mutated != ""


def test_family_b_sqli_evasion_mutations():
    """Verify Family B SQLi produces held-out evasion patterns (double encoding, hex, concat)."""
    payload = "admin' OR '1'='1"
    mutations = [mutate_payload(payload, family="B", attack_type="sqli", seed=s) for s in range(15)]
    has_double_encoding = any("%25" in m for m in mutations)
    has_hex_or_concat = any("0x" in m or "CONCAT" in m or "concat" in m for m in mutations)
    assert has_double_encoding or has_hex_or_concat


def test_family_b_xss_evasion_mutations():
    """Verify Family B XSS produces held-out evasion patterns (double encoding, hex entities, charCode)."""
    payload = "<script>alert(1)</script>"
    mutations = [mutate_payload(payload, family="B", attack_type="xss", seed=s) for s in range(15)]
    has_double_encoding = any("%25" in m for m in mutations)
    has_entities_or_tags = any("&#x" in m or "fromCharCode" in m or "<details" in m or "<audio" in m or "<video" in m or "<svg" in m for m in mutations)
    assert has_double_encoding or has_entities_or_tags


def test_strict_family_disjointness():
    """Verify that Family A registry shares zero function objects with Family B registry."""
    set_a = set(FAMILY_A_SQLI + FAMILY_A_XSS + FAMILY_A_BENIGN)
    set_b = set(FAMILY_B_SQLI + FAMILY_B_XSS + FAMILY_B_BENIGN)
    overlap = set_a.intersection(set_b)
    assert len(overlap) == 0, f"Disjoint violation! Overlapping mutators: {overlap}"


def test_measure_normalisation_absorption():
    """Verify absorption rate calculation against the gateway's normalizer."""
    samples = [
        ("q=' or 1=1", "sqli"),
        ("msg=<script>alert(1)</script>", "xss"),
        ("user=admin'--", "sqli"),
        ("input=<img src=x onerror=alert(1)>", "xss"),
        ("page=products", "benign"),
    ]
    res_a = measure_normalisation_absorption(samples, family="A", seed=42)
    assert res_a["total_tested"] == 5
    assert 0.0 <= res_a["absorption_rate"] <= 1.0
    assert 0.0 <= res_a["survival_rate"] <= 1.0
    assert res_a["absorbed_count"] + res_a["survived_count"] == 5
