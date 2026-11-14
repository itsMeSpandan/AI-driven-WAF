"""
Re-export from shared waf_common package to guarantee zero train/serve skew.
"""

from waf_common.normalizer import (
    NormalisedRequest,
    SQL_COMMENT_PATTERN,
    WHITESPACE_PATTERN,
    decode_recursively,
    normalise_request,
    parse_body_content,
    sanitize_token,
)

__all__ = [
    "NormalisedRequest",
    "SQL_COMMENT_PATTERN",
    "WHITESPACE_PATTERN",
    "decode_recursively",
    "normalise_request",
    "parse_body_content",
    "sanitize_token",
]
