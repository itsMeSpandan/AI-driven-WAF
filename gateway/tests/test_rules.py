"""
Unit tests and ReDoS safety benchmarks for WAF Rule Engine (Task 4).
Verifies positive and negative matching for all rules and measures ReDoS resistance.
"""

import time
import pytest
from gateway.rules import RULES, evaluate_rules


# Positive and negative test cases for each rule
RULE_TEST_CASES = [
    # SQLi
    ("SQLI-001", "get /items?q=1 or 1=1", "get /items?q=shoes"),
    ("SQLI-002", "get /api?query=union select 1,2", "get /api?query=union workers"),
    ("SQLI-003", "post /db drop table users", "post /db drop by later"),
    ("SQLI-004", "get /search where id=1--", "get /search where id=123"),
    ("SQLI-005", "get /info information_schema.tables", "get /info about our company"),
    ("SQLI-006", "get /sleep?t=sleep(5)", "get /sleep?category=pillows"),
    ("SQLI-007", "get /items; drop table sessions", "get /items;category=shoes"),
    ("SQLI-008", "get /file load_file('/etc/passwd')", "get /file loading files"),
    ("SQLI-009", "get /q?hex=0x31323334", "get /q?hex=0x0"),
    ("SQLI-010", "get /login?u=admin' --", "get /login?u=admin_user"),

    # XSS
    ("XSS-001", "get /msg?q=<script>alert(1)", "get /msg?q=typescript"),
    ("XSS-002", "get /msg?q=</script>", "get /msg?q=clean text"),
    ("XSS-003", "get /img?onload=alert(1)", "get /img?load=progress"),
    ("XSS-004", "get /img?onerror=alert(1)", "get /img?error=404"),
    ("XSS-005", "get /btn?onclick=alert(1)", "get /btn?click=true"),
    ("XSS-006", "get /uri?link=javascript:alert(1)", "get /uri?link=https://google.com"),
    ("XSS-007", "get /uri?link=vbscript:msgbox(1)", "get /uri?link=clean"),
    ("XSS-008", "get /page?embed=<iframe src=evil>", "get /page?frame=photo"),
    ("XSS-009", "get /icon?svg=<svg onload=alert(1)>", "get /icon?format=svg"),
    ("XSS-010", "get /test?fn=alert(1)", "get /test?fn=calculate"),
    ("XSS-011", "get /cookie?val=document.cookie", "get /cookie?val=chocolate_cookie"),

    # Path Traversal
    ("TRAV-001", "get /file?p=../../etc/passwd", "get /file?p=images/logo.png"),
    ("TRAV-002", "get /file?p=/etc/passwd", "get /file?p=/products/list"),
    ("TRAV-003", "get /file?p=c:\\windows\\system32", "get /file?p=c:\\app\\docs"),

    # Command Injection
    ("CMD-001", "get /ping?ip=127.0.0.1; whoami", "get /ping?ip=127.0.0.1"),
    ("CMD-002", "get /run?cmd=/bin/sh", "get /run?cmd=start_worker"),

    # Scanner
    ("SCAN-001", "get /test user-agent:sqlmap/1.7.11", "get /test user-agent:mozilla/5.0"),
    ("SCAN-002", "get /test?scanner=nikto", "get /test?scanner=barcode"),
    ("SCAN-003", "get /.env", "get /environment-friendly-products"),
]


@pytest.mark.parametrize("rule_id, positive_sample, negative_sample", RULE_TEST_CASES)
def test_each_rule_positive_and_negative(rule_id, positive_sample, negative_sample):
    rule = next((r for r in RULES if r.id == rule_id), None)
    assert rule is not None, f"Rule {rule_id} not found in RULES registry"

    assert rule.pattern.search(positive_sample) is not None, (
        f"Rule {rule_id} failed to match positive sample: {positive_sample}"
    )
    assert rule.pattern.search(negative_sample) is None, (
        f"Rule {rule_id} falsely matched negative sample: {negative_sample}"
    )


def test_redos_safety_on_adversarial_long_inputs():
    """Verify that all rules evaluate in microseconds on long repeating strings (no catastrophic backtracking)."""
    adversarial_payloads = [
        "a" * 10000,
        ("select " * 500) + "from users",
        ("<script" * 500) + "alert",
        ("or 1=1 " * 500),
        ("../" * 1000) + "passwd",
        ("0x" + "a" * 5000),
        ";" * 5000,
    ]

    for rule in RULES:
        for payload in adversarial_payloads:
            t0 = time.perf_counter()
            rule.pattern.search(payload)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            # Each evaluation must complete in < 20 ms
            assert elapsed_ms < 20.0, (
                f"ReDoS detected on rule {rule.id}! Took {elapsed_ms:.2f} ms on adversarial input."
            )


def test_evaluate_rules_returns_highest_severity():
    # Input with both medium (SQLI-009) and critical (SQLI-002)
    composite = "get /test?hex=0x31323334&q=union select 1,2"
    hit = evaluate_rules(composite)
    assert hit is not None
    assert hit.severity == "critical"
    assert hit.category == "sqli"


def test_evaluate_rules_clean_input_returns_none():
    clean = "get /products?category=apparel&sort=price_asc user-agent:mozilla/5.0"
    hit = evaluate_rules(clean)
    assert hit is None
