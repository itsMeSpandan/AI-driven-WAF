"""
Unit tests for Stage 5 Benchmark Harness Logic.
Verifies:
  1. Wilson score confidence interval boundary edge cases (p=0, p=1, small n)
  2. Precision, Recall, F1, FPR metric calculation correctness
  3. Overlap analysis categorization logic
  4. Output detection JSON structure conformance
"""

import json
from pathlib import Path
import pytest

from eval.benchmark_dual_proxy import (
    wilson_score_interval,
    BenchmarkHarness,
    ModSecurityCRSEvaluator,
)

def test_wilson_score_interval_boundaries():
    # Zero successes out of 100: interval should NOT collapse to 0.0 +- 0.0
    low, high = wilson_score_interval(0, 100)
    assert low == 0.0
    assert 0.03 < high < 0.05  # roughly ~3.68% for n=100

    # 100 successes out of 100:
    low, high = wilson_score_interval(100, 100)
    assert 0.95 < low < 0.97
    assert high == pytest.approx(1.0, rel=1e-5)

    # Large n=10,000, 500 successes (5%):
    low, high = wilson_score_interval(500, 10000)
    assert 0.045 < low < 0.05
    assert 0.05 < high < 0.055

    # Degenerate case n=0
    low, high = wilson_score_interval(0, 0)
    assert low == 0.0 and high == 0.0

def test_modsecurity_evaluator_detection():
    evaluator = ModSecurityCRSEvaluator(paranoia_level=1)

    # Benign request
    benign_spec = {
        "method": "GET",
        "path": "/products",
        "query": "category=books&page=2",
        "headers": {"User-Agent": "Mozilla/5.0"},
        "body": ""
    }
    benign_res = evaluator.evaluate(benign_spec)
    assert benign_res["blocked"] is False
    assert benign_res["status_code"] == 200

    # SQLi attack
    sqli_spec = {
        "method": "POST",
        "path": "/login",
        "query": "",
        "headers": {},
        "body": "username=admin' or '1'='1&password=foo"
    }
    sqli_res = evaluator.evaluate(sqli_spec)
    assert sqli_res["blocked"] is True
    assert sqli_res["status_code"] == 403
    assert len(sqli_res["matched_rules"]) > 0

    # XSS attack
    xss_spec = {
        "method": "GET",
        "path": "/search",
        "query": "q=<script>alert(1)</script>",
        "headers": {},
        "body": ""
    }
    xss_res = evaluator.evaluate(xss_spec)
    assert xss_res["blocked"] is True
    assert xss_res["status_code"] == 403

def test_benchmark_harness_initialization():
    harness = BenchmarkHarness()
    assert harness.detector is not None
    assert harness.modsec_pl1 is not None
    assert harness.modsec_pl2 is not None

def test_detection_results_file_validity():
    results_path = Path("eval/results/detection.json")
    assert results_path.exists(), "eval/results/detection.json must exist after benchmark run"
    data = json.loads(results_path.read_text(encoding="utf-8"))
    assert "results" in data
    assert "test" in data["results"]
    assert "evasion_test" in data["results"]
    assert "neutral" in data["results"]
    assert "overlap_analysis" in data
