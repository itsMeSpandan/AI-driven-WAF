"""
Token attribution and diagnostic explainer (gateway/explainer.py).
Implements Stage 3 Task 5 per TRD 2.4 & STAGES.md:
  - Fast execution: Only computes explanations for flagged/blocked requests
  - Linear model feature attribution: n-gram contribution = coef_i * tf_idf_i
  - Character offset mapping in canonical text with overlapping span merging
  - Interpretable dense lexical feature notes (XSS markers, SQL keywords, special char ratio)
  - Seamless fallback for rule hits and fail-safe exception handling
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

from gateway.detector import MLResult, detector
from gateway.normalizer import NormalisedRequest
from gateway.rules import RULES

if TYPE_CHECKING:
    from gateway.pipeline import RuleResult

logger = logging.getLogger("waf-explainer")

# Cache rule descriptions for quick lookup
RULE_DESCRIPTIONS = {r.id: r.description for r in RULES}

_CACHED_TFIDF_FEATURE_NAMES = None


def _get_feature_names(tfidf) -> Any:
    global _CACHED_TFIDF_FEATURE_NAMES
    if _CACHED_TFIDF_FEATURE_NAMES is None:
        _CACHED_TFIDF_FEATURE_NAMES = tfidf.get_feature_names_out()
    return _CACHED_TFIDF_FEATURE_NAMES

LEXICAL_FEATURE_NAMES = [
    "length",
    "special_char_ratio",
    "digit_ratio",
    "shannon_entropy",
    "sql_keyword_count",
    "xss_marker_count",
    "quote_comment_count",
    "max_token_length",
]


def _merge_spans(spans: List[Dict[str, Any]], canonical_text: str) -> List[Dict[str, Any]]:
    """
    Sorts and merges overlapping or contiguous character intervals.
    Ensures canonical_text[start:end] == text for every token.
    """
    if not spans:
        return []

    # Sort spans by start offset ascending, then length descending
    spans.sort(key=lambda s: (s["start"], -(s["end"] - s["start"])))

    merged: List[Dict[str, Any]] = []
    curr = dict(spans[0])

    for nxt in spans[1:]:
        if nxt["start"] <= curr["end"]:
            # Overlapping or contiguous interval
            curr["end"] = max(curr["end"], nxt["end"])
            curr["weight"] = max(curr["weight"], nxt["weight"])
            curr["text"] = canonical_text[curr["start"] : curr["end"]]
            curr["token"] = canonical_text[curr["start"] : curr["end"]]
        else:
            merged.append(curr)
            curr = dict(nxt)

    merged.append(curr)
    # Re-verify and clean
    return [
        s for s in merged
        if s["start"] >= 0 and s["end"] <= len(canonical_text) and s["text"] == canonical_text[s["start"] : s["end"]]
    ]


def extract_linear_token_attributions(
    canonical_text: str,
    top_k: int = 3,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Extracts top contributing character n-grams and dense lexical features
    from the active Logistic Regression pipeline.
    """
    if not detector.is_loaded or detector.pipeline is None or not canonical_text:
        return [], []

    tokens: List[Dict[str, Any]] = []
    features: List[Dict[str, Any]] = []

    try:
        pipeline = detector.pipeline
        features_step = pipeline.named_steps.get("features")
        clf = pipeline.named_steps.get("classifier")

        if features_step is None or clf is None or not hasattr(clf, "coef_"):
            return [], []

        # Transformer 0 is TF-IDF Vectorizer
        tfidf = features_step.transformer_list[0][1]
        feature_names = _get_feature_names(tfidf)
        num_tfidf = len(feature_names)

        # 1. N-Gram Contributions
        X_tfidf = tfidf.transform([canonical_text])
        coefs = clf.coef_[0]

        raw_candidates: List[Tuple[str, float]] = []
        for idx_in_sparse, feat_idx in enumerate(X_tfidf.indices):
            weight = float(X_tfidf.data[idx_in_sparse] * coefs[feat_idx])
            if weight > 0.001:  # Only positive malicious contributions
                ngram_token = feature_names[feat_idx]
                raw_candidates.append((ngram_token, weight))

        # Sort candidate n-grams by contribution descending
        raw_candidates.sort(key=lambda x: x[1], reverse=True)

        # Map n-grams to character offsets in canonical text
        mapped_spans: List[Dict[str, Any]] = []
        text_lower = canonical_text.lower()

        for token, w in raw_candidates[:20]:
            clean_token = token.strip()
            if not clean_token or len(clean_token) < 2:
                continue
            # Find all occurrences in canonical text
            start_pos = 0
            while True:
                found_idx = text_lower.find(clean_token.lower(), start_pos)
                if found_idx == -1:
                    break
                end_pos = found_idx + len(clean_token)
                actual_substr = canonical_text[found_idx:end_pos]
                mapped_spans.append({
                    "token": actual_substr,
                    "text": actual_substr,
                    "start": found_idx,
                    "end": end_pos,
                    "weight": round(w, 4),
                })
                start_pos = found_idx + 1

        # Merge overlapping spans
        tokens = _merge_spans(mapped_spans, canonical_text)
        # Limit to top_k spans sorted by weight
        tokens.sort(key=lambda s: s["weight"], reverse=True)
        tokens = tokens[:top_k]

        # 2. Dense Lexical Features Contribution
        # Transformer 1 is the Lexical Feature Pipeline
        if len(coefs) > num_tfidf:
            lexical_step = features_step.transformer_list[1][1]
            extractor = lexical_step.named_steps.get("extractor")
            if extractor:
                lex_vals = extractor.transform([canonical_text])[0]
                for i, name in enumerate(LEXICAL_FEATURE_NAMES):
                    val = float(lex_vals[i])
                    # Flag notable features with positive model weight
                    if name == "xss_marker_count" and val > 0:
                        features.append({"name": name, "value": int(val), "note": f"{int(val)} XSS marker(s) detected"})
                    elif name == "sql_keyword_count" and val > 0:
                        features.append({"name": name, "value": int(val), "note": f"{int(val)} SQL keyword(s) detected"})
                    elif name == "special_char_ratio" and val >= 0.15:
                        features.append({"name": name, "value": round(val, 2), "note": "Elevated special character ratio"})
                    elif name == "max_token_length" and val >= 40:
                        features.append({"name": name, "value": int(val), "note": "Excessive unbroken token length"})

    except Exception as e:
        logger.warning("Error calculating linear token attributions: %s", e)

    return tokens, features


def explain_request(
    norm: Optional[NormalisedRequest],
    rule: RuleResult,
    ml: MLResult,
    verdict_action: str = "allow",
) -> Dict[str, Any]:
    """
    Generate human-readable diagnostic explanation for an HTTP inspection decision.
    Only computes detailed token attributions for 'block' and 'flag' verdicts.
    """
    # Performance guard: Clean allowed requests bypass attribution entirely
    if verdict_action == "allow":
        return {
            "summary": "Clean request",
            "attack_type": "benign",
            "matched_rule": None,
            "top_tokens": [],
            "features": [],
        }

    try:
        canonical_text = norm.canonical_text if norm else ""
        top_tokens: List[Dict[str, Any]] = []
        features: List[Dict[str, Any]] = []

        # 1. Linear token attribution & lexical feature inspection
        if canonical_text:
            top_tokens, features = extract_linear_token_attributions(canonical_text, top_k=3)

        # 2. Rule hit attribution integration
        matched_rule_info = None
        if rule.hit:
            matched_rule_info = {
                "id": rule.rule_id,
                "category": rule.attack_type,
                "pattern": rule.matched_pattern,
                "description": RULE_DESCRIPTIONS.get(rule.rule_id, "OWASP signature pattern violation"),
            }
            # If matched pattern exists in canonical text, ensure it is included in top_tokens
            if rule.matched_pattern and canonical_text:
                pat = rule.matched_pattern
                idx = canonical_text.lower().find(pat.lower())
                if idx != -1:
                    rule_span = {
                        "token": canonical_text[idx : idx + len(pat)],
                        "text": canonical_text[idx : idx + len(pat)],
                        "start": idx,
                        "end": idx + len(pat),
                        "weight": 1.0,
                    }
                    top_tokens.insert(0, rule_span)
                    top_tokens = _merge_spans(top_tokens, canonical_text)[:5]

        # 3. High-level diagnostic summary
        attack_type = rule.attack_type if rule.hit else ml.attack_type
        if rule.hit and ml.score >= 0.5:
            summary = f"Signature hit ({rule.rule_id}) confirmed by ML threat score {ml.score:.2f}"
        elif rule.hit:
            summary = f"Blocked by signature {rule.rule_id}: {RULE_DESCRIPTIONS.get(rule.rule_id, rule.attack_type)}"
        elif ml.score >= 0.5:
            summary = f"ML threat detected: Likely {attack_type} (anomaly score {ml.score:.2f})"
        else:
            summary = f"Policy violation: {attack_type}"

        return {
            "summary": summary,
            "attack_type": attack_type,
            "matched_rule": rule.rule_id if rule.hit else None,
            "matched_rule_detail": matched_rule_info,
            "top_tokens": top_tokens,
            "features": features,
            "canonical_text": canonical_text,
        }

    except Exception as exc:
        logger.error("Explainer error (falling back gracefully): %s", exc)
        return {
            "summary": f"Threat detected: {rule.attack_type or ml.attack_type or 'anomaly'}",
            "attack_type": rule.attack_type or ml.attack_type or "anomaly",
            "matched_rule": rule.rule_id if rule.hit else None,
            "matched_rule_detail": {"id": rule.rule_id} if rule.hit else None,
            "top_tokens": [],
            "features": [],
            "canonical_text": norm.canonical_text if norm else "",
        }
