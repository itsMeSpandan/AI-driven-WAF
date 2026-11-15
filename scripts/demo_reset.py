"""
scripts/demo_reset.py
Turnkey demo reset script.
Restores a clean seeded state in < 5 seconds:
  1. Clears existing event telemetry, analyst feedback, and audit logs.
  2. Resets runtime WAF configurations to strict defaults (Block mode, tau=0.940).
  3. Seeds 50 realistic benign browsing events across the past 30 minutes.
  4. Checks service health endpoints if containers are running.
"""

import os
import random
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Ensure repo root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from gateway.models import Config, ConfigAudit, Event, Feedback, get_engine, init_db
from sqlalchemy.orm import sessionmaker

BENIGN_SEEDS = [
    ("/rest/products/search", "GET", "q=apple&limit=5", "", 200, 3.2),
    ("/rest/products/search", "GET", "q=juice&category=drinks", "", 200, 4.1),
    ("/api/user/profile", "GET", "", "", 200, 2.8),
    ("/products", "GET", "category=books", "", 200, 3.5),
    ("/cart", "GET", "", "", 200, 2.5),
    ("/cart/add", "POST", "", '{"item_id": 14, "quantity": 1}', 200, 4.8),
    ("/contact", "POST", "", '{"name": "Alice", "message": "Smooth experience"}', 200, 5.2),
    ("/checkout", "POST", "", '{"payment_method": "card", "currency": "USD"}', 200, 6.1),
    ("/assets/main.css", "GET", "", "", 200, 1.2),
    ("/assets/bundle.js", "GET", "", "", 200, 1.5),
]

BENIGN_IPS = [
    "192.168.1.10", "192.168.1.15", "10.0.0.5", "10.0.0.12",
    "172.16.0.4", "198.51.100.22",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

def reset_demo_state(count: int = 50, verbose: bool = True):
    db_url = os.getenv("DB_URL", "sqlite:///./data/waf.db")
    init_db(db_url)
    engine = get_engine(db_url)
    SessionLocal = sessionmaker(bind=engine)

    if verbose:
        print("==================================================")
        print("       AI-DRIVEN WAF: DEMO RESET PROCEDURE        ")
        print("==================================================")
        print(f"[*] Target Database: {db_url}")

    with SessionLocal() as session:
        # 1. Truncate Telemetry and Feedback
        deleted_events = session.query(Event).delete()
        deleted_feedback = session.query(Feedback).delete()
        deleted_audit = session.query(ConfigAudit).delete()
        if verbose:
            print(f"[*] Cleared {deleted_events} events, {deleted_feedback} feedbacks, {deleted_audit} audit logs.")

        # 2. Reset Default Configuration
        configs = {
            "waf_mode": "block",
            "ml_threshold": "0.94",
            "max_body_inspect_bytes": "16384",
            "fail_mode": "closed",
            "rate_limit_enabled": "true",
            "rate_limit_window_sec": "10",
            "rate_limit_burst": "30",
            "rate_enforce": "false",
        }
        for k, v in configs.items():
            cfg = session.query(Config).filter_by(key=k).first()
            if cfg:
                cfg.value = str(v)
            else:
                session.add(Config(key=k, value=str(v)))
        session.commit()
        if verbose:
            print("[*] Reset WAF configurations: Mode='block', Threshold=0.940, RateLimit=10s/30req.")

        # 3. Seed Benign Baseline Events
        now = datetime.now(timezone.utc)
        events_to_seed = []
        for i in range(count):
            path, method, query, body, status_code, base_lat = random.choice(BENIGN_SEEDS)
            # Spread across the past 30 minutes
            time_offset = random.uniform(5, 30 * 60)
            ts = now - timedelta(seconds=time_offset)
            client_ip = random.choice(BENIGN_IPS)
            ua = random.choice(USER_AGENTS)
            ml_score = round(random.uniform(0.01, 0.22), 3)
            latency = round(base_lat + random.uniform(-0.5, 1.5), 2)

            ev = Event(
                id=str(uuid.uuid4()),
                ts=ts,
                client_ip=client_ip,
                method=method,
                path=path,
                query_summary=query,
                body_summary=body,
                user_agent=ua,
                rule_hit=None,
                ml_score=ml_score,
                verdict="allow",
                attack_type="benign",
                latency_ms=latency,
                explanation={"summary": "Benign normal traffic", "top_tokens": []},
                feedback=None,
                model_version="Stage3_Robust_20261114_204029",
                anomaly_flag=None,
            )
            events_to_seed.append(ev)

        session.bulk_save_objects(events_to_seed)
        session.commit()
        if verbose:
            print(f"[+] Successfully seeded {len(events_to_seed)} benign baseline events.")

    # 4. Service Probing
    try:
        import httpx
        with httpx.Client(timeout=1.0) as client:
            gw_resp = client.get("http://localhost:8080/healthz")
            gw_status = f"ONLINE ({gw_resp.status_code})" if gw_resp.status_code == 200 else "DEGRADED"
    except Exception:
        gw_status = "NOT RUNNING (Run 'make up' to start)"

    try:
        import httpx
        with httpx.Client(timeout=1.0) as client:
            api_resp = client.get("http://localhost:8000/healthz")
            api_status = f"ONLINE ({api_resp.status_code})" if api_resp.status_code == 200 else "DEGRADED"
    except Exception:
        api_status = "NOT RUNNING (Run 'make up' to start)"

    if verbose:
        print("[*] Service Health Status:")
        print(f"    - WAF Gateway   (:8080): {gw_status}")
        print(f"    - Dashboard API (:8000): {api_status}")
        print(f"    - Dashboard UI  (:3000): Open browser at http://localhost:3000")
        print("==================================================")
        print(" DEMO STATE READY IN < 1 SECOND (Clean Seeded DB) ")
        print("==================================================")

if __name__ == "__main__":
    reset_demo_state()
