"""
Sensitive data masking utility.
Prevents credentials, session cookies, and tokens from being stored in logs or DB.
"""

import re
from typing import Dict, List

# Regex to match sensitive keys (case-insensitive)
SENSITIVE_KEY_PATTERN = re.compile(
    r"(pass(word|wd)?|secret|token|api_?key|auth|credit_?card|cvv)",
    re.IGNORECASE,
)

SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "x-api-key",
}


def mask_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Mask credentials and authentication headers."""
    masked: Dict[str, str] = {}
    for k, v in headers.items():
        k_lower = k.lower()
        if k_lower in SENSITIVE_HEADERS or SENSITIVE_KEY_PATTERN.search(k_lower):
            masked[k] = "[REDACTED]"
        else:
            masked[k] = v
    return masked


def mask_params(params: Dict[str, List[str]]) -> Dict[str, List[str]]:
    """Mask values for any parameter whose key matches sensitive keywords."""
    masked: Dict[str, List[str]] = {}
    for k, vals in params.items():
        if SENSITIVE_KEY_PATTERN.search(k):
            masked[k] = ["[REDACTED]"] * len(vals)
        else:
            masked[k] = vals
    return masked


def mask_query_string(query_string: str) -> str:
    """Mask sensitive parameter values in a raw URL query string."""
    if not query_string:
        return ""

    import urllib.parse

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


def mask_body_summary(body_str: str) -> str:
    """Mask occurrences of sensitive patterns in json or urlencoded body snippets."""
    if not body_str:
        return ""

    # Replace JSON key values: "password": "xyz" -> "password": "[REDACTED]"
    masked = re.sub(
        r'("(?:password|passwd|token|secret|api_key|access_token)"\s*:\s*)"([^"]*)"',
        r'\1"[REDACTED]"',
        body_str,
        flags=re.IGNORECASE,
    )
    # Replace form fields: password=xyz -> password=[REDACTED]
    masked = re.sub(
        r'((?:^|[&?])(?:password|passwd|token|secret|api_key)=)([^&]*)',
        r'\1[REDACTED]',
        masked,
        flags=re.IGNORECASE,
    )
    return masked
