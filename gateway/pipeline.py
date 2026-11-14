"""
WAF inspection pipeline interface and decision logic.
Implements Stage 2 Task 5:
  - Real rule layer integration (rules.py)
  - Real ML detector scoring (detector.py)
  - Dynamic thresholding and Monitor vs Block mode decision logic
  - Structured explanation generation
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from gateway.detector import MLResult, detector
from gateway.normalizer import NormalisedRequest
from gateway.rules import evaluate_rules


@dataclass
class RuleResult:
    """Outcome of rule-based pattern matching."""

    hit: bool = False
    rule_id: Optional[str] = None
    attack_type: Optional[str] = None
    matched_pattern: Optional[str] = None


@dataclass
class Verdict:
    """Final decision regarding whether to allow, flag, or block the request."""

    action: str  # 'allow', 'flag', 'block'
    attack_type: str
    rule_hit: Optional[str]
    ml_score: float
    explanation: Dict[str, Any] = field(default_factory=dict)
    model_version: str = "none"


def rule_check(norm: NormalisedRequest) -> RuleResult:
    """
    Evaluates bounded regex signatures from rules.py against canonical text.
    """
    hit = evaluate_rules(norm.canonical_text)
    if hit:
        return RuleResult(
            hit=True,
            rule_id=hit.rule_id,
            attack_type=hit.category,
            matched_pattern=hit.matched_substring,
        )
    return RuleResult(hit=False)


def ml_score(norm: NormalisedRequest) -> MLResult:
    """
    Evaluates trained ML detector pipeline against canonical text.
    Falls back gracefully to rule-only MLResult if model is absent.
    """
    return detector.score(norm.canonical_text)


def explain(
    norm: Optional[NormalisedRequest],
    rule: RuleResult,
    ml: MLResult,
) -> Dict[str, Any]:
    """
    Generates structured per-request diagnostic explanation.
    """
    summary = "Clean request"
    if rule.hit and ml.score >= 0.26:
        summary = f"Rule hit: {rule.rule_id} ({rule.attack_type}) + ML anomaly score {ml.score:.4f}"
    elif rule.hit:
        summary = f"Rule hit: {rule.rule_id} ({rule.attack_type})"
    elif ml.score >= 0.26:
        summary = f"ML anomaly score: {ml.score:.4f} (type: {ml.attack_type})"

    return {
        "top_tokens": [rule.matched_pattern] if rule.matched_pattern else [],
        "matched_rule": rule.rule_id if rule.hit else None,
        "matched_pattern": rule.matched_pattern,
        "model_version": ml.model_version,
        "confidence": ml.confidence,
        "summary": summary,
    }


def decide(
    rule: RuleResult,
    ml: MLResult,
    mode: str = "block",
    threshold: float = 0.26,
    norm: Optional[NormalisedRequest] = None,
) -> Verdict:
    """
    Determines verdict based on rule hit and ML threshold comparison.
    Respects WAF mode:
      - 'block': threats are rejected with HTTP 403
      - 'monitor': threats are permitted through but tagged as 'flag'
    """
    is_threat = rule.hit or (ml.score >= threshold)
    attack_type = "benign"

    if rule.hit:
        attack_type = rule.attack_type or "rule_violation"
    elif ml.score >= threshold:
        attack_type = ml.attack_type or "ml_threat"

    if is_threat:
        action = "block" if mode.lower() == "block" else "flag"
    else:
        action = "allow"

    expl = explain(norm, rule, ml)

    return Verdict(
        action=action,
        attack_type=attack_type,
        rule_hit=rule.rule_id if rule.hit else None,
        ml_score=ml.score,
        explanation=expl,
        model_version=ml.model_version,
    )
