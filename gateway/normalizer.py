"""
Request normalisation module.
Builds a canonical, decoded representation of incoming HTTP requests for inspection.
Follows TRD 2.3:
  - Iterative URL-decoding (bounded depth)
  - HTML entity decoding
  - Unicode NFKC normalisation
  - Stripping SQL inline comments (/* ... */)
  - Lower-casing
  - Whitespace collapsing
  - Duplicate parameter merging
  - JSON and form body parsing
  - Inspection cap bounding
"""

from __future__ import annotations

import html
import json
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class NormalisedRequest:
    """Canonical representation of an HTTP request for inspection and explainability."""

    canonical_text: str
    method: str
    path: str
    query_params: Dict[str, List[str]] = field(default_factory=dict)
    body_params: Dict[str, List[str]] = field(default_factory=dict)
    body_raw: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    is_truncated: bool = False


# Regex to strip SQL inline comments: /* ... */
SQL_COMMENT_PATTERN = re.compile(r"/\*.*?\*/", re.DOTALL)
# Regex to collapse multiple whitespace characters
WHITESPACE_PATTERN = re.compile(r"\s+")


def decode_recursively(text: str, max_depth: int = 3) -> str:
    """
    Apply iterative URL-decoding up to max_depth to defeat multi-encoded payloads.
    Also handles HTML entity decoding and Unicode NFKC normalization.
    """
    if not text:
        return ""

    current = text
    # Iterative URL decode
    for _ in range(max_depth):
        try:
            decoded = urllib.parse.unquote(current)
        except Exception:
            break
        if decoded == current:
            break
        current = decoded

    # HTML entity unescape
    current = html.unescape(current)

    # Unicode NFKC normalization (turns fullwidth, compatibility characters into canonical forms)
    current = unicodedata.normalize("NFKC", current)

    return current


def sanitize_token(text: str) -> str:
    """
    Sanitizes an individual string token:
    1. Multi-pass decode (URL, HTML entity, NFKC)
    2. Strip SQL inline comments (replace with a space)
    3. Lowercase
    4. Collapse whitespace
    """
    if not text:
        return ""

    decoded = decode_recursively(text)
    # Replace SQL inline comments with space so `SEL/**/ECT` becomes `sel ect`
    no_comments = SQL_COMMENT_PATTERN.sub(" ", decoded)
    # Lowercase
    lowered = no_comments.lower()
    # Collapse whitespace
    collapsed = WHITESPACE_PATTERN.sub(" ", lowered).strip()
    return collapsed


def parse_body_content(
    body_bytes: bytes,
    content_type: str,
    max_inspect_bytes: int = 16384,
) -> tuple[Dict[str, List[str]], str, bool]:
    """
    Inspects body up to max_inspect_bytes, parsing JSON or form data.
    Returns (params_dict, raw_text_summary, is_truncated).
    """
    is_truncated = False
    if len(body_bytes) > max_inspect_bytes:
        inspect_bytes = body_bytes[:max_inspect_bytes]
        is_truncated = True
    else:
        inspect_bytes = body_bytes

    body_text = inspect_bytes.decode("utf-8", errors="replace")
    params: Dict[str, List[str]] = {}

    content_type_lower = content_type.lower()

    if "application/json" in content_type_lower:
        try:
            parsed_json = json.loads(body_text)
            _extract_json_strings(parsed_json, params)
        except Exception:
            # If invalid or truncated JSON, treat as raw text
            pass
    elif (
        "application/x-www-form-urlencoded" in content_type_lower
        or "multipart/form-data" in content_type_lower
    ):
        try:
            parsed_qs = urllib.parse.parse_qs(body_text, keep_blank_values=True)
            for k, v in parsed_qs.items():
                params[k] = v
        except Exception:
            pass

    return params, body_text, is_truncated


def _extract_json_strings(obj: Any, out_params: Dict[str, List[str]], prefix: str = "") -> None:
    """Flatten JSON keys and values into a string parameter dictionary."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            key_name = f"{prefix}.{k}" if prefix else str(k)
            _extract_json_strings(v, out_params, key_name)
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            key_name = f"{prefix}[{idx}]"
            _extract_json_strings(item, out_params, key_name)
    else:
        k = prefix or "body"
        val = str(obj)
        out_params.setdefault(k, []).append(val)


def normalise_request(
    method: str,
    path: str,
    query_string: str = "",
    headers: Optional[Dict[str, str]] = None,
    body_bytes: bytes = b"",
    max_inspect_bytes: int = 16384,
) -> NormalisedRequest:
    """
    Core normalisation pipeline per TRD 2.3.
    Constructs a single canonical string representing all inspectable parts of the request.
    """
    headers = headers or {}

    # 1. Normalize method and path
    norm_method = sanitize_token(method)
    norm_path = sanitize_token(path)

    # 2. Parse and normalize query parameters
    query_params: Dict[str, List[str]] = {}
    if query_string:
        try:
            raw_qs = urllib.parse.parse_qs(query_string, keep_blank_values=True)
            for k, vals in raw_qs.items():
                norm_key = sanitize_token(k)
                norm_vals = [sanitize_token(v) for v in vals]
                query_params.setdefault(norm_key, []).extend(norm_vals)
        except Exception:
            # Fallback for malformed query string
            query_params["_raw"] = [sanitize_token(query_string)]

    # 3. Selected headers for inspection
    selected_headers: Dict[str, str] = {}
    inspect_header_keys = ("user-agent", "referer", "content-type", "origin")
    for hk, hv in headers.items():
        hk_lower = hk.lower()
        if hk_lower in inspect_header_keys:
            selected_headers[hk_lower] = sanitize_token(hv)

    # 4. Parse body up to inspection cap
    content_type = headers.get("content-type", "")
    body_params, body_raw, is_truncated = parse_body_content(
        body_bytes, content_type, max_inspect_bytes=max_inspect_bytes
    )

    # Normalize body params
    norm_body_params: Dict[str, List[str]] = {}
    for bk, bvals in body_params.items():
        nbk = sanitize_token(bk)
        nbvals = [sanitize_token(bv) for bv in bvals]
        norm_body_params.setdefault(nbk, []).extend(nbvals)

    # 5. Build Canonical Text
    # Order: method, path, sorted query params (key=val), sorted body params, headers, raw body
    parts: List[str] = [norm_method, norm_path]

    # Deterministic query representation
    if query_params:
        q_elements = []
        for k in sorted(query_params.keys()):
            for v in sorted(query_params[k]):
                q_elements.append(f"{k}={v}")
        parts.append("&".join(q_elements))

    # Deterministic body representation
    if norm_body_params:
        b_elements = []
        for k in sorted(norm_body_params.keys()):
            for v in sorted(norm_body_params[k]):
                b_elements.append(f"{k}={v}")
        parts.append("&".join(b_elements))
    elif body_raw and not norm_body_params:
        # If no key-value structure, include sanitized body raw text
        sanitized_body = sanitize_token(body_raw)
        if sanitized_body:
            parts.append(sanitized_body)

    # Include headers
    for hk in sorted(selected_headers.keys()):
        parts.append(f"{hk}:{selected_headers[hk]}")

    canonical_text = " ".join([p for p in parts if p]).strip()

    return NormalisedRequest(
        canonical_text=canonical_text,
        method=norm_method,
        path=norm_path,
        query_params=query_params,
        body_params=norm_body_params,
        body_raw=body_raw,
        headers=selected_headers,
        is_truncated=is_truncated,
    )
