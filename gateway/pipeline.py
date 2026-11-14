"""
WAF inspection pipeline interface and decision logic.
Provides stub stages for Stage 1 so Stage 2 can plug in detection without refactor.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from gateway.normalizer import NormalisedRequest


@dataclass
class RuleResult:
    """Outcome of rule-based pattern matching."""

    hit: bool = False
    rule_id: Optional[str] = None
    attack_type: Optional[str] = None
    matched_pattern: Optional[str] = None


@dataclass
class MLResult:
    """Outcome of ML model classification and scoring."""

    score: float = 0.0
    attack_type: str = "benign"
    confidence: float = 0.0


@dataclass
class Verdict:
    """Final decision regarding whether to allow, flag, or block the request."""

    action: str  # 'allow', 'flag', 'block'
    attack_type: str
    rule_hit: Optional[str]
    ml_score: float
    explanation: Dict[str, Any] = field(default_factory=dict)


def rule_check(norm: NormalisedRequest) -> RuleResult:
    """
    Stage 1 Stub: Rule engine.
    Always returns no hit. Will be loaded with regex signatures in Stage 2.
    """
    return RuleResult(hit=False)


def ml_score(norm: NormalisedRequest) -> MLResult:
    """
    Stage 1 Stub: ML detector.
    Always returns benign with 0.0 score. Real model plugged in Stage 2.
    """
    return MLResult(score=0.0, attack_type="benign", confidence=1.0)


def explain(
    norm: Optional[NormalisedRequest],
    rule: RuleResult,
    ml: MLResult,
) -> Dict[str, Any]:
    """
    Stage 1 Stub: Per-request explainer.
    Returns token highlights and rule diagnostics.
    """
    return {
        "top_tokens": [],
        "matched_rule": rule.rule_id if rule.hit else None,
        "summary": (
            f"Rule hit: {rule.rule_id}"
            if rule.hit
            else f"ML anomaly score: {ml.score:.3f}"
        ),
    }


def decide(
    rule: RuleResult,
    ml: MLResult,
    mode: str = "block",
    threshold: float = 0.75,
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
    )
