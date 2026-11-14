"""
Seed demo data generator.
Generates ~2,000 realistic synthetic inspection events across the last 24 hours.
Populates SQLite/PG database with benign, SQLi, XSS, and bot anomaly telemetry.
"""

from __future__ import annotations

import os
import random
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Ensure repo root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from gateway.models import Config, Event, get_engine, init_db
from sqlalchemy.orm import sessionmaker

BENIGN_PATHS = [
    ("/products", "GET", "category=books&limit=10", ""),
    ("/products/12", "GET", "", ""),
    ("/api/user/profile", "GET", "", ""),
    ("/cart", "GET", "", ""),
    ("/cart/add", "POST", "", '{"item_id": 42, "quantity": 1}'),
    ("/checkout", "POST", "", '{"payment_method": "card", "currency": "USD"}'),
    ("/rest/products/search", "GET", "q=laptop&sort=asc", ""),
    ("/contact", "POST", "", '{"name": "Alice", "message": "Great service!"}'),
    ("/assets/main.css", "GET", "", ""),
    ("/assets/bundle.js", "GET", "", ""),
    ("/health", "GET", "", ""),
]

SQLI_PAYLOADS = [
    ("' OR '1'='1", "SQLI_TAUTOLOGY_01", 0.94),
    ("' OR 1=1 --", "SQLI_COMMENT_BYPASS_02", 0.91),
    ("1' UNION SELECT 1,username,password FROM users--", "SQLI_UNION_SELECT_01", 0.98),
    ("admin' --", "SQLI_AUTH_BYPASS_03", 0.88),
    ("1; DROP TABLE sessions;--", "SQLI_STACKED_QUERIES_01", 0.95),
    ("' UNION ALL SELECT NULL,NULL,table_name FROM information_schema.tables--", "SQLI_SCHEMA_ENUM_01", 0.97),
]

XSS_PAYLOADS = [
    ("<script>alert(1)</script>", "XSS_SCRIPT_TAG_01", 0.96),
    ("<img src=x onerror=alert(document.domain)>", "XSS_EVENT_HANDLER_02", 0.92),
    ("<svg/onload=alert('xss')>", "XSS_SVG_PAYLOAD_01", 0.89),
    ("javascript:alert(1)", "XSS_URI_SCHEME_01", 0.85),
    ("<iframe src=\"javascript:alert(`xss`)\"></iframe>", "XSS_IFRAME_02", 0.93),
]

BOT_PROBES = [
    ("/.env", "GET", "PROBE_SENSITIVE_FILES_01", 0.87),
    ("/wp-login.php", "GET", "PROBE_WP_ADMIN_01", 0.85),
    ("/admin/config.php", "GET", "PROBE_ADMIN_PORTAL_02", 0.89),
    ("/etc/passwd", "GET", "PROBE_LFI_01", 0.95),
    ("/cgi-bin/test-cgi", "GET", "PROBE_SHELLSHOCK_01", 0.91),
]

BENIGN_IPS = [
    "192.168.1.10", "192.168.1.15", "10.0.0.5", "10.0.0.12",
    "172.16.0.4", "172.16.0.9", "198.51.100.22", "198.51.100.45",
]

ATTACKER_IPS = [
    "45.33.32.156", "185.220.101.5", "194.26.29.112",
    "91.240.118.172", "103.251.167.20", "193.106.191.66",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "curl/8.4.0",
    "python-requests/2.31.0",
    "sqlmap/1.7.11#stable",
]


def seed_database(total_events: int = 2000) -> None:
    db_url = os.getenv("DB_URL", "sqlite:///./data/waf.db")
    init_db(db_url)
    engine = get_engine(db_url)
    SessionLocal = sessionmaker(bind=engine)

    print(f"[*] Seeding ~{total_events} events into database: {db_url}")

    now = datetime.now(timezone.utc)
    events_to_create = []

    # Distribution:
    # 80% Benign (~1600)
    # 12% SQLi (~240)
    # 6% XSS (~120)
    # 2% Bot/Anomaly (~40)

    for i in range(total_events):
        event_id = str(uuid.uuid4())
        # Random distribution across the past 24 hours
        time_offset = random.uniform(0, 24 * 3600)
        ts = now - timedelta(seconds=time_offset)

        category = random.choices(
            ["benign", "sqli", "xss", "bot"],
            weights=[80, 12, 6, 2],
            k=1,
        )[0]

        if category == "benign":
            path, method, query, body = random.choice(BENIGN_PATHS)
            client_ip = random.choice(BENIGN_IPS)
            ua = random.choice(USER_AGENTS[:3])
            rule_hit = None
            ml_score = round(random.uniform(0.01, 0.28), 3)
            verdict = "allow"
            attack_type = "benign"
            latency = round(random.uniform(3.0, 14.0), 2)
            explanation = {"summary": "No malicious patterns detected", "top_tokens": []}

        elif category == "sqli":
            payload, rule_name, base_score = random.choice(SQLI_PAYLOADS)
            method = random.choice(["GET", "POST"])
            path = random.choice(["/rest/products/search", "/api/search", "/rest/user/login"])
            query = f"q={payload}" if method == "GET" else ""
            body = f'{{"username": "admin", "query": "{payload}"}}' if method == "POST" else ""
            client_ip = random.choice(ATTACKER_IPS)
            ua = random.choice(USER_AGENTS[3:])
            rule_hit = rule_name
            ml_score = round(min(0.99, base_score + random.uniform(-0.03, 0.03)), 3)
            verdict = "block"
            attack_type = "sqli"
            latency = round(random.uniform(10.0, 26.0), 2)
            tokens = [
                {"token": t, "weight": round(random.uniform(0.2, 0.5), 3)}
                for t in payload.split()[:3]
            ]
            explanation = {
                "matched_rule": rule_name,
                "top_tokens": tokens,
                "summary": f"SQL injection detected via signature {rule_name}",
            }

        elif category == "xss":
            payload, rule_name, base_score = random.choice(XSS_PAYLOADS)
            method = random.choice(["GET", "POST"])
            path = random.choice(["/feedback", "/comment", "/profile/bio"])
            query = f"msg={payload}" if method == "GET" else ""
            body = f'{{"comment": "{payload}"}}' if method == "POST" else ""
            client_ip = random.choice(ATTACKER_IPS)
            ua = random.choice(USER_AGENTS[2:])
            rule_hit = rule_name
            ml_score = round(min(0.98, base_score + random.uniform(-0.04, 0.04)), 3)
            verdict = "block"
            attack_type = "xss"
            latency = round(random.uniform(8.0, 22.0), 2)
            explanation = {
                "matched_rule": rule_name,
                "top_tokens": [{"token": "<script>", "weight": 0.42}],
                "summary": f"Cross-site scripting payload matched {rule_name}",
            }

        else:  # bot probe
            path, method, rule_name, base_score = random.choice(BOT_PROBES)
            query = ""
            body = ""
            client_ip = random.choice(ATTACKER_IPS)
            ua = random.choice(USER_AGENTS[3:])
            rule_hit = rule_name
            ml_score = round(base_score, 3)
            verdict = "block"
            attack_type = "bot_anomaly"
            latency = round(random.uniform(5.0, 15.0), 2)
            explanation = {
                "matched_rule": rule_name,
                "top_tokens": [],
                "summary": "Targeted scanning of sensitive file/endpoint",
            }

        events_to_create.append(
            Event(
                id=event_id,
                ts=ts,
                client_ip=client_ip,
                method=method,
                path=path,
                query_summary=query,
                body_summary=body,
                user_agent=ua,
                rule_hit=rule_hit,
                ml_score=ml_score,
                verdict=verdict,
                attack_type=attack_type,
                latency_ms=latency,
                explanation=explanation,
                feedback=None,
            )
        )

    with SessionLocal() as session:
        # Clear existing events
        session.query(Event).delete()
        # Add new batch
        session.bulk_save_objects(events_to_create)
        session.commit()

    print(f"[+] Successfully seeded {len(events_to_create)} events into database.")


if __name__ == "__main__":
    seed_database()
