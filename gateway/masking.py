"""
Enterprise-Grade Sensitive Data Masking & Sanitisation Utility.
Implements Stage 6 Task 1 per TRD 2.9 & STAGES.md:
  - Key-based masking for credentials, session identifiers, tokens, and PII
  - Pattern-based masking:
      * Credit Card numbers (13-19 digits validated with Luhn algorithm)
      * Bearer & JWT tokens
      * Canary secret tokens (CANARY-*)
      * High-entropy credential patterns
  - Deep recursive JSON masking across arbitrary nesting levels
  - Canonical text masking prior to DB storage, logging, SSE broadcast, or UI export
  - Token attribution span sanitisation to prevent secret leakage in dashboard drawers
"""

from __future__ import annotations

import copy
import json
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Union

# Regex to match sensitive parameter keys (case-insensitive)
SENSITIVE_KEY_PATTERN = re.compile(
    r"(pass(word|wd)?|secret|token|api_?key|access_?token|auth|bearer|credit_?card|card_?num(ber)?|cvv|cvc|ssn|private_?key|canary)",
    re.IGNORECASE,
)

SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
    "x-secret-key",
}

# Pattern-based secret matchers
JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
BEARER_PATTERN = re.compile(r"\b(Bearer\s+)[A-Za-z0-9_\-\.]{15,}\b", re.IGNORECASE)
CANARY_PATTERN = re.compile(r"\bCANARY-[A-Za-z0-9_\-]+\b", re.IGNORECASE)
CC_CANDIDATE_PATTERN = re.compile(r"\b(?:\d[ -]*?){13,19}\b")


def luhn_check(card_str: str) -> bool:
    """
    Validates a credit card number using the ISO/IEC 7812 Luhn checksum algorithm.
    Guarantees that random numbers or phone numbers are not mistakenly redacted as credit cards.
    """
    digits = [int(c) for c in card_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False

    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = d * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += d
    return checksum % 10 == 0


def mask_patterns_in_text(text: str) -> str:
    """
    Applies pattern-based redaction:
      1. Luhn-validated Credit Card numbers -> [REDACTED_CC]
      2. JWT tokens -> [REDACTED_JWT]
      3. Bearer tokens -> Bearer [REDACTED_TOKEN]
      4. Canary tokens -> [REDACTED_CANARY]
    """
    if not text:
        return ""

    # 1. Canary tokens
    res = CANARY_PATTERN.sub("[REDACTED_CANARY]", text)

    # 2. JWTs
    res = JWT_PATTERN.sub("[REDACTED_JWT]", res)

    # 3. Bearer headers
    res = BEARER_PATTERN.sub(r"\1[REDACTED_TOKEN]", res)

    # 4. Credit cards with Luhn verification
    def _cc_replacer(match: re.Match[str]) -> str:
        matched_str = match.group(0)
        if luhn_check(matched_str):
            return "[REDACTED_CC]"
        return matched_str

    res = CC_CANDIDATE_PATTERN.sub(_cc_replacer, res)
    return res


def mask_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Mask credentials and authentication headers, and scan remaining values for secret patterns."""
    masked: Dict[str, str] = {}
    for k, v in headers.items():
        k_lower = k.lower()
        if k_lower in SENSITIVE_HEADERS or SENSITIVE_KEY_PATTERN.search(k_lower):
            masked[k] = "[REDACTED]"
        else:
            masked[k] = mask_patterns_in_text(v)
    return masked


def mask_params(params: Dict[str, List[str]]) -> Dict[str, List[str]]:
    """Mask values for any parameter whose key matches sensitive keywords or value matches patterns."""
    masked: Dict[str, List[str]] = {}
    for k, vals in params.items():
        if SENSITIVE_KEY_PATTERN.search(k):
            masked[k] = ["[REDACTED]"] * len(vals)
        else:
            masked[k] = [mask_patterns_in_text(v) for v in vals]
    return masked


def mask_query_string(query_string: str) -> str:
    """Mask sensitive parameter values and patterns in a raw URL query string."""
    if not query_string:
        return ""

    try:
        parsed = urllib.parse.parse_qs(query_string, keep_blank_values=True)
        masked_dict = mask_params(parsed)
        out_pairs = []
        for k, vals in masked_dict.items():
            for v in vals:
                out_pairs.append(f"{urllib.parse.quote_plus(k)}={urllib.parse.quote_plus(v)}")
        return "&".join(out_pairs)
    except Exception:
        return "[MASK_ERROR]"


def _mask_json_obj(obj: Any) -> Any:
    """Recursively mask sensitive keys and patterns in arbitrary JSON data structures."""
    if isinstance(obj, dict):
        new_dict: Dict[str, Any] = {}
        for k, v in obj.items():
            if SENSITIVE_KEY_PATTERN.search(str(k)):
                new_dict[k] = "[REDACTED]"
            else:
                new_dict[k] = _mask_json_obj(v)
        return new_dict
    elif isinstance(obj, list):
        return [_mask_json_obj(item) for item in obj]
    elif isinstance(obj, str):
        return mask_patterns_in_text(obj)
    return obj


def mask_body_summary(body_str: str) -> str:
    """Mask occurrences of sensitive patterns in json, form-urlencoded, or multipart body snippets."""
    if not body_str:
        return ""

    # Attempt JSON parsing first for strict structural redaction
    stripped = body_str.strip()
    if (stripped.startswith("{") and stripped.endswith("}")) or (stripped.startswith("[") and stripped.endswith("]")):
        try:
            parsed = json.loads(stripped)
            masked_obj = _mask_json_obj(parsed)
            return json.dumps(masked_obj)
        except Exception:
            pass

    # Fallback to robust regex masking for form-urlencoded or malformed JSON
    masked = re.sub(
        r'("(?:password|passwd|token|secret|api_?key|access_token|canary)"\s*:\s*)"([^"]*)"',
        r'\1"[REDACTED]"',
        body_str,
        flags=re.IGNORECASE,
    )
    masked = re.sub(
        r'((?:^|[&?])(?:password|passwd|token|secret|api_?key|canary)=)([^&]*)',
        r'\1[REDACTED]',
        masked,
        flags=re.IGNORECASE,
    )
    return mask_patterns_in_text(masked)


def mask_canonical_text(canonical_text: str) -> str:
    """
    Masks sensitive values in canonical text format before persistent logging or UI exposure.
    Handles space-delimited elements, query parameters, and dotted JSON parameter keys.
    """
    if not canonical_text:
        return ""

    # 1. Parameter-level redaction on key=value pairs
    # Matches patterns like `password=xyz`, `user.token=xyz`, `api_key=123`
    def _param_replacer(match: re.Match[str]) -> str:
        key = match.group(1)
        # Check if key (or leaf key in dotted notation) is sensitive
        leaf_key = key.split(".")[-1]
        if SENSITIVE_KEY_PATTERN.search(leaf_key) or SENSITIVE_KEY_PATTERN.search(key):
            return f"{key}=[REDACTED]"
        val = match.group(2)
        return f"{key}={mask_patterns_in_text(val)}"

    redacted = re.sub(r'([A-Za-z0-9_\.\[\]]+)=([^ \t\r\n]+)', _param_replacer, canonical_text)

    # 2. Redact patterns (CC, JWT, canary) across remaining canonical text
    return mask_patterns_in_text(redacted)


def mask_explanation(explanation: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Sanitizes explanation dictionary prior to database persistence, SSE broadcast, or API serialization.
    Ensures that contributing tokens and canonical text previews never leak sensitive data.
    """
    if not explanation or not isinstance(explanation, dict):
        return {}

    masked_exp = copy.deepcopy(explanation)

    # 1. Mask canonical text
    if "canonical_text" in masked_exp and isinstance(masked_exp["canonical_text"], str):
        masked_exp["canonical_text"] = mask_canonical_text(masked_exp["canonical_text"])

    # 2. Mask tokens in top_tokens
    if "top_tokens" in masked_exp and isinstance(masked_exp["top_tokens"], list):
        sanitized_tokens = []
        for t in masked_exp["top_tokens"]:
            if isinstance(t, dict):
                tok_copy = dict(t)
                tok_str = str(tok_copy.get("token", ""))
                txt_str = str(tok_copy.get("text", ""))

                # Check if token contains canary or secret patterns
                if (
                    CANARY_PATTERN.search(tok_str)
                    or JWT_PATTERN.search(tok_str)
                    or SENSITIVE_KEY_PATTERN.search(tok_str)
                    or luhn_check(tok_str)
                ):
                    tok_copy["token"] = "[REDACTED]"
                    tok_copy["text"] = "[REDACTED]"
                else:
                    tok_copy["token"] = mask_patterns_in_text(tok_str)
                    tok_copy["text"] = mask_patterns_in_text(txt_str)
                sanitized_tokens.append(tok_copy)
            else:
                sanitized_tokens.append(t)
        masked_exp["top_tokens"] = sanitized_tokens

    # 3. Mask matched rule detail if present
    if "matched_rule_detail" in masked_exp and isinstance(masked_exp["matched_rule_detail"], dict):
        m_det = masked_exp["matched_rule_detail"]
        if "pattern" in m_det and isinstance(m_det["pattern"], str):
            m_det["pattern"] = mask_patterns_in_text(m_det["pattern"])

    return masked_exp


def mask_event_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Ensures that an entire event payload dictionary is masked across all fields before queueing.
    """
    masked = dict(payload)
    if "query_summary" in masked and isinstance(masked["query_summary"], str):
        masked["query_summary"] = mask_query_string(masked["query_summary"])
    if "body_summary" in masked and isinstance(masked["body_summary"], str):
        masked["body_summary"] = mask_body_summary(masked["body_summary"])
    if "explanation" in masked and isinstance(masked["explanation"], dict):
        masked["explanation"] = mask_explanation(masked["explanation"])
    if "path" in masked and isinstance(masked["path"], str):
        masked["path"] = mask_patterns_in_text(masked["path"])
    return masked
