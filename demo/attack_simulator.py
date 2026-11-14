"""
Attack Traffic Simulator for AI-Driven WAF.
Generates controlled, reproducible benign and textbook attack traffic
exclusively targeted against the local WAF Gateway.
Follows Defensive Safety Guidelines:
  - Refuses non-local targets unless explicitly overridden with --i-own-this-target
  - Uses only short, public-domain textbook educational vectors
"""

from __future__ import annotations

import argparse
import random
import sys
import time
import urllib.parse
from pathlib import Path

import httpx

PAYLOADS_DIR = Path(__file__).resolve().parent / "payloads"
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def load_lines(filename: str) -> list[str]:
    filepath = PAYLOADS_DIR / filename
    if not filepath.exists():
        return []
    with open(filepath, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def check_target_safety(target_url: str, override_flag: bool) -> None:
    parsed = urllib.parse.urlparse(target_url)
    hostname = parsed.hostname or "localhost"

    if hostname not in LOCAL_HOSTS and not override_flag:
        print("\n[!] SAFETY ERROR: Target host is external: " + hostname)
        print("    This attack simulator is strictly restricted to local lab environments.")
        print("    To run against an authorized target, pass --i-own-this-target explicitly.\n")
        sys.exit(1)


def run_simulator(
    target: str,
    count: int,
    types: list[str],
    rate: float,
    override_safety: bool,
) -> None:
    check_target_safety(target, override_safety)

    benign_paths = load_lines("benign.txt") or ["/products?q=shoes", "/about", "/contact"]
    sqli_payloads = load_lines("sqli.txt") or ["' OR '1'='1", "admin' --"]
    xss_payloads = load_lines("xss.txt") or ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]

    delay_between_requests = 1.0 / rate if rate > 0 else 0.5
    target_clean = target.rstrip("/")

    print("==================================================================")
    print("           AI-Driven WAF — Attack & Telemetry Simulator            ")
    print("==================================================================")
    print(f" Target Gateway : {target_clean}")
    print(f" Request Count  : {count}")
    print(f" Traffic Classes: {', '.join(types)}")
    print(f" Rate (req/sec) : {rate} (delay ~{delay_between_requests:.2f}s)")
    print("------------------------------------------------------------------\n")

    results = {"total": 0, "blocked": 0, "allowed": 0, "errors": 0}
    latencies: list[float] = []

    with httpx.Client(timeout=10.0) as client:
        for idx in range(1, count + 1):
            chosen_type = random.choice(types)
            start_t = time.perf_counter()

            try:
                if chosen_type == "benign":
                    rel_path = random.choice(benign_paths)
                    url = f"{target_clean}{rel_path}"
                    resp = client.get(url)

                elif chosen_type == "sqli":
                    payload = random.choice(sqli_payloads)
                    encoded_payload = urllib.parse.quote(payload)
                    url = f"{target_clean}/rest/products/search?q={encoded_payload}"
                    resp = client.get(url)

                elif chosen_type == "xss":
                    payload = random.choice(xss_payloads)
                    encoded_payload = urllib.parse.quote(payload)
                    url = f"{target_clean}/feedback?comment={encoded_payload}"
                    resp = client.get(url)

                else:
                    url = f"{target_clean}/"
                    resp = client.get(url)

                elapsed_ms = (time.perf_counter() - start_t) * 1000.0
                latencies.append(elapsed_ms)

                waf_verdict = resp.headers.get("x-waf-verdict", "unknown")
                req_id = resp.headers.get("x-waf-request-id", "none")[:8]

                results["total"] += 1
                if resp.status_code == 403 or waf_verdict == "block":
                    results["blocked"] += 1
                    status_badge = "\033[91m[BLOCKED 403]\033[0m"
                else:
                    results["allowed"] += 1
                    status_badge = "\033[92m[ALLOWED " + str(resp.status_code) + "]\033[0m"

                print(
                    f"[{idx:03d}/{count:03d}] {chosen_type.upper():<7} -> {status_badge} "
                    f"latency: {elapsed_ms:5.1f}ms | req_id: {req_id} | url: {url[:60]}"
                )

            except Exception as req_err:
                results["errors"] += 1
                print(f"[{idx:03d}/{count:03d}] {chosen_type.upper():<7} -> [ERROR] {req_err}")

            time.sleep(delay_between_requests)

    # Print Summary Table
    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
    print("\n------------------------------------------------------------------")
    print("                     SIMULATION SUMMARY                           ")
    print("------------------------------------------------------------------")
    print(f" Total Requests Transmitted : {results['total']}")
    print(f" Requests Blocked (403)     : {results['blocked']}")
    print(f" Requests Allowed (Clean)   : {results['allowed']}")
    print(f" Transport Errors           : {results['errors']}")
    print(f" Mean Latency Overhead      : {avg_latency:.2f} ms")
    print("==================================================================\n")


def main():
    parser = argparse.ArgumentParser(
        description="Controlled HTTP attack and traffic simulator for AI WAF testing.",
    )
    parser.add_argument(
        "--target",
        default="http://localhost:8080",
        help="Target WAF gateway URL (default: http://localhost:8080)",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=20,
        help="Number of HTTP requests to transmit (default: 20)",
    )
    parser.add_argument(
        "--types",
        default="sqli,xss,benign",
        help="Comma-separated traffic classes (default: sqli,xss,benign)",
    )
    parser.add_argument(
        "--rate",
        type=float,
        default=2.0,
        help="Transmit rate in requests per second (default: 2.0)",
    )
    parser.add_argument(
        "--i-own-this-target",
        action="store_true",
        help="Explicit confirmation allowing simulation against non-local authorized targets.",
    )
    args = parser.parse_args()

    active_types = [t.strip().lower() for t in args.types.split(",") if t.strip()]
    run_simulator(
        target=args.target,
        count=args.count,
        types=active_types,
        rate=args.rate,
        override_safety=args.i_own_this_target,
    )


if __name__ == "__main__":
    main()
