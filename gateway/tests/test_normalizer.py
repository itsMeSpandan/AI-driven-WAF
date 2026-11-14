"""
Unit tests for the request normalisation module (TRD 2.3 & Task 5).
"""

from gateway.normalizer import (
    decode_recursively,
    normalise_request,
    sanitize_token,
)


def test_benign_request_unaltered():
    """Verify standard benign queries remain clean and semantically intact."""
    norm = normalise_request(
        method="GET",
        path="/api/products",
        query_string="category=books&sort=price_asc",
        headers={"user-agent": "Mozilla/5.0", "content-type": "application/json"},
    )
    assert norm.method == "get"
    assert norm.path == "/api/products"
    assert "category=books" in norm.canonical_text
    assert "sort=price_asc" in norm.canonical_text
    assert "user-agent:mozilla/5.0" in norm.canonical_text
    assert not norm.is_truncated


def test_url_double_and_triple_decoding():
    """Verify iterative decoding unwraps multiple layers of percent-encoding."""
    # '%2527' -> '%27' -> "'"
    double_encoded = "%2527%2520or%25201=1"
    decoded = decode_recursively(double_encoded, max_depth=3)
    assert decoded == "' or 1=1"

    norm = normalise_request(
        method="GET",
        path="/items",
        query_string=f"q={double_encoded}",
    )
    assert "q=' or 1=1" in norm.canonical_text


def test_html_entity_decoding():
    """Verify HTML entities are properly unescaped."""
    html_encoded = "&lt;script&gt;alert(1)&lt;/script&gt;"
    decoded = sanitize_token(html_encoded)
    assert decoded == "<script>alert(1)</script>"

    # In form bodies, '&' is the parameter separator, so entities are sent as '%26lt;'
    norm_form = normalise_request(
        method="POST",
        path="/comment",
        body_bytes=b"text=%26lt%3Bscript%26gt%3Balert(1)%26lt%3B/script%26gt%3B",
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert "text=<script>alert(1)</script>" in norm_form.canonical_text

    # In JSON bodies
    norm_json = normalise_request(
        method="POST",
        path="/comment",
        body_bytes=b'{"comment": "&lt;script&gt;alert(1)&lt;/script&gt;"}',
        headers={"content-type": "application/json"},
    )
    assert "comment=<script>alert(1)</script>" in norm_json.canonical_text


def test_unicode_nfkc_normalization():
    """Verify full-width characters convert to ASCII canonical representation."""
    # Fullwidth `<script>`: \uff1c\uff53\uff43\uff52\uff49\uff50\uff54\uff1e
    fullwidth_script = "\uff1c\uff53\uff43\uff52\uff49\uff50\uff54\uff1e"
    decoded = sanitize_token(fullwidth_script)
    assert decoded == "<script>"


def test_sql_inline_comment_stripping():
    """Verify SQL inline comments (/* ... */) are replaced with spaces to avoid keyword obfuscation."""
    obfuscated_sql = "UN/**/ION/**/SEL/**/ECT 1,2,3"
    sanitized = sanitize_token(obfuscated_sql)
    assert sanitized == "un ion sel ect 1,2,3"


def test_case_folding_and_whitespace_collapse():
    """Verify mixed-case folding and whitespace normalization."""
    mixed_case = "   sElEcT   *   fRoM   uSeRs   "
    sanitized = sanitize_token(mixed_case)
    assert sanitized == "select * from users"


def test_duplicate_parameter_handling():
    """Verify duplicate parameters are preserved deterministically in canonical output."""
    norm = normalise_request(
        method="GET",
        path="/filter",
        query_string="tag=db&tag=security&tag=auth",
    )
    # Merged and sorted
    assert "tag=auth&tag=db&tag=security" in norm.canonical_text


def test_json_body_extraction():
    """Verify nested JSON bodies are flattened and extracted."""
    json_payload = b'{"query": {"sql": "SELECT 1", "author": "Alice"}, "limit": 10}'
    norm = normalise_request(
        method="POST",
        path="/graphql",
        headers={"content-type": "application/json"},
        body_bytes=json_payload,
    )
    assert "query.sql=select 1" in norm.canonical_text
    assert "query.author=alice" in norm.canonical_text
    assert "limit=10" in norm.canonical_text


def test_body_inspection_cap():
    """Verify request bodies exceeding max_inspect_bytes are capped and flagged."""
    large_body = b"A" * 20000
    norm = normalise_request(
        method="POST",
        path="/upload",
        body_bytes=large_body,
        max_inspect_bytes=1000,
    )
    assert norm.is_truncated is True
    assert len(norm.body_raw) == 1000
