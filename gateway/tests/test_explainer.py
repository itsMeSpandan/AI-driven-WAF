"""
Unit tests for Stage 3 Token Attribution Explainer (gateway/tests/test_explainer.py).
Verifies:
  - Deterministic attribution
  - Character offset invariant: canonical_text[start:end] == token_text
  - Rule-only match attribution
  - Clean request performance bypass
  - Robust error handling and non-crashing behavior
"""

import pytest
from gateway.detector import MLResult, detector
from gateway.explainer import explain_request, extract_linear_token_attributions
from gateway.normalizer import normalise_request
from gateway.pipeline import RuleResult, decide, rule_check, ml_score


def test_explainer_clean_request_bypass():
    """Clean allowed requests should bypass attribution and return empty top_tokens immediately."""
    norm = normalise_request("GET", "/index.html", "user=alice", {}, b"")
    rule = RuleResult(hit=False)
    ml = MLResult(score=0.01, attack_type="benign", confidence=0.99)

    expl = explain_request(norm, rule, ml, verdict_action="allow")
    assert expl["summary"] == "Clean request"
    assert expl["top_tokens"] == []
    assert expl["features"] == []
    assert expl["matched_rule"] is None


def test_explainer_character_offset_invariant():
    """Every token returned must strictly satisfy canonical_text[start:end] == token['text']."""
    raw_query = "id=1' UNION SELECT username, password FROM users--"
    norm = normalise_request("GET", "/api/search", raw_query, {}, b"")
    rule = rule_check(norm)
    ml = ml_score(norm)

    expl = explain_request(norm, rule, ml, verdict_action="block")

    assert len(expl["top_tokens"]) > 0
    canonical_text = norm.canonical_text

    for item in expl["top_tokens"]:
        start = item["start"]
        end = item["end"]
        text = item["text"]
        token = item["token"]

        assert 0 <= start < end <= len(canonical_text)
        assert canonical_text[start:end] == text
        assert canonical_text[start:end] == token
        assert item["weight"] > 0


def test_explainer_deterministic():
    """Repeated calls for the same payload produce identical explanations and token weights."""
    norm = normalise_request("POST", "/comment", "", {}, b"<script>alert(1)</script>")
    rule = rule_check(norm)
    ml = ml_score(norm)

    expl1 = explain_request(norm, rule, ml, verdict_action="block")
    expl2 = explain_request(norm, rule, ml, verdict_action="block")

    assert expl1["summary"] == expl2["summary"]
    assert expl1["top_tokens"] == expl2["top_tokens"]
    assert expl1["features"] == expl2["features"]


def test_explainer_rule_only_hit():
    """If ML score is low but a rule matches, explanation properly captures rule info and span."""
    norm = normalise_request("GET", "/debug", "test=etc/passwd", {}, b"")
    rule = RuleResult(
        hit=True,
        rule_id="PATH_TRAVERSAL_01",
        attack_type="path_traversal",
        matched_pattern="etc/passwd",
    )
    ml = MLResult(score=0.05, attack_type="benign", confidence=0.95)

    expl = explain_request(norm, rule, ml, verdict_action="block")
    assert expl["matched_rule"] == "PATH_TRAVERSAL_01"
    assert expl["matched_rule_detail"] is not None
    assert expl["matched_rule_detail"]["id"] == "PATH_TRAVERSAL_01"
    assert "PATH_TRAVERSAL_01" in expl["summary"]

    # Matched pattern should be mapped in top_tokens
    assert any(t["token"] == "etc/passwd" for t in expl["top_tokens"])


def test_explainer_lexical_features():
    """Anomalous requests surface notable lexical features."""
    norm = normalise_request("GET", "/login", "user=' OR '1'='1", {}, b"")
    rule = rule_check(norm)
    ml = ml_score(norm)

    expl = explain_request(norm, rule, ml, verdict_action="block")
    assert "features" in expl
    # Should include sql_keyword_count or special_char_ratio
    feature_names = [f["name"] for f in expl["features"]]
    assert len(feature_names) > 0


def test_explainer_fail_safe():
    """Explainer never crashes on None, empty string, or malformed inputs."""
    rule = RuleResult(hit=False)
    ml = MLResult(score=0.95, attack_type="sqli")

    # None norm
    expl = explain_request(None, rule, ml, verdict_action="block")
    assert isinstance(expl, dict)
    assert expl["top_tokens"] == []

    # Empty canonical text
    empty_norm = normalise_request("GET", "", "", {}, b"")
    expl2 = explain_request(empty_norm, rule, ml, verdict_action="block")
    assert isinstance(expl2, dict)


def test_decide_attaches_stage3_explanation():
    """Pipeline decide() attaches structured Stage 3 explanation to Verdict."""
    norm = normalise_request("GET", "/search", "q=<svg/onload=alert(1)>", {}, b"")
    rule = rule_check(norm)
    ml = ml_score(norm)

    verdict = decide(rule, ml, mode="block", threshold=0.5, norm=norm)
    assert verdict.action == "block"
    assert "top_tokens" in verdict.explanation
    assert len(verdict.explanation["top_tokens"]) > 0
    assert "summary" in verdict.explanation
