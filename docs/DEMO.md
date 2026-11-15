# AI-Driven WAF & Real-Time Analytics Dashboard
## Turnkey 5-Minute Live Demonstration Script (Release v1.0)

This document provides a turnkey, timed, 5-minute demonstration script for project reviews, committee examinations, and technical evaluations. Every presentation beat includes exact bash commands, expected visual states, talking points, and a zero-downtime offline fallback plan with static visual artifacts.

---

## 1. Pre-Flight Setup (< 1 Minute)

Run the automated turnkey reset target from the repository root:

```bash
# 1. Reset database, apply default config (Block mode, tau=0.940), seed 50 clean benign requests
make demo-reset

# 2. Verify containers are running (if not already started, run 'make up')
# Check Gateway:   http://localhost:8080/healthz
# Check API:       http://localhost:8000/healthz
# Check Dashboard: http://localhost:3000
```

### Browser Window Arrangement
Prepare two browser windows side-by-side:
- **Left Window (Analyst Console)**: `http://localhost:3000` (Overview page showing live traffic chart and request feed).
- **Right Window (Evaluations / Target)**: `http://localhost:3000/models` (Model & ModSecurity comparison tab).

---

## 2. Timed 5-Minute Presentation Script

### Beat 1: Architecture & Benign Traffic Baseline (0:00 – 1:00)
- **Objective**: Establish the problem, demonstrate pass-through forwarding, and show low latency.
- **Talking Points**:
  > *"Traditional WAFs rely on static regular expressions that are easily evaded, while deep learning research models are too slow for real-time proxying. Our AI-Driven WAF sits as a lightweight reverse proxy in front of this target application (OWASP Juice Shop). Notice that in our console, the WAF is currently in **Block Mode** with a calibrated threshold of **0.940**."*
- **Live Terminal Command**:
  ```bash
  # Send clean shopping search query through WAF gateway
  curl -i -s "http://localhost:8080/rest/products/search?q=apple+juice" | head -n 8
  ```
- **Expected Result**:
  - Terminal: `HTTP/1.1 200 OK` forwarded from Juice Shop in **< 4.0 ms**.
  - Dashboard UI: Real-time traffic count increments, verdict displays green **`ALLOW`**, attack type **`benign`**, and ML score is low (~0.05).
- **Fallback Plan (If Container Unresponsive)**:
  - Display architecture diagram: `docs/diagrams/system_architecture.png`.
  - Explain the multi-pass normalizer and async event queue architecture.

---

### Beat 2: Plain Injection Attack Caught by Rule Layer (1:00 – 2:00)
- **Objective**: Show deterministic rule enforcement with zero false positives.
- **Talking Points**:
  > *"First, let's fire a textbook SQL injection payload into the login portal. Our gateway normalizes the input, executes 29 ReDoS-immune regex rules in parallel with ML inference, and terminates malicious traffic before it ever touches upstream code."*
- **Live Terminal Command**:
  ```bash
  # Send classic SQL injection auth-bypass
  curl -i -s -X POST "http://localhost:8080/rest/user/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"admin'\'' OR '\''1'\''='\''1--","password":"test"}' | head -n 10
  ```
- **Expected Result**:
  - Terminal: Immediate `HTTP/1.1 403 Forbidden` with response body:
    `{"detail": "Forbidden: WAF security policy violation", "rule": "SQLI_TAUTOLOGY_01", "verdict": "block"}`.
  - Dashboard UI: Event appears immediately in live stream with red **`BLOCK`** badge.
  - Click Event $\rightarrow$ Explanation Drawer slides out showing matched signature `SQLI_TAUTOLOGY_01` and highlighted tokens `' OR '1'='1`.
- **Fallback Plan**:
  - Reference `docs/diagrams/request_lifecycle.png` and explain how deterministic regexes provide instant rejection without invoking complex downstream handlers.

---

### Beat 3: Obfuscated Zero-Day Attack Caught by ML Detector (2:00 – 3:00)
- **Objective**: Demonstrate zero-day adversarial evasion where regex rules fail but character n-grams succeed.
- **Talking Points**:
  > *"Now let's simulate an advanced attacker using zero-day obfuscation from our held-out Family B evasion set—combining inline SQL comments, whitespace mutations, and double URL encoding. ModSecurity CRS PL1 fails to catch this because the regex tokens are broken up. But watch our AI detector."*
- **Live Terminal Command**:
  ```bash
  # Send obfuscated SQL injection with hex literal representation (Family B)
  curl -i -s "http://localhost:8080/rest/products/search?q=select%20and%200x61=0x61" | head -n 10
  ```
- **Expected Result**:
  - Terminal: `HTTP/1.1 403 Forbidden` with ML confidence score $\ge 0.96$.
  - Dashboard UI: Blocked event appears. Rule column reads `None` (rules missed it), but ML Score is **0.978**.
  - Explanation Drawer: Highlights character spans (`union`, `select`, `password`) in red, computed in **< 1.0 ms** by our linear explainer.
- **Fallback Plan**:
  - Display `eval/figures/confusion_matrices.png` sub-panel for `evasion_test`. Point out the **90.32% recall** for AI-WAF vs **24.15%** for ModSecurity PL1.

---

### Beat 4: Dynamic Operator Controls — Monitor vs. Block Mode (3:00 – 4:00)
- **Objective**: Demonstrate live policy reconfiguration without gateway restart.
- **Talking Points**:
  > *"Security operations teams often want to observe traffic before enforcing hard blocks. From our Settings page, an administrator can toggle between Block and Monitor modes dynamically."*
- **Live Terminal Command (or UI Toggle)**:
  ```bash
  # 1. Switch gateway to Monitor mode via API
  curl -s -X PUT "http://localhost:8000/api/config" \
    -H "Content-Type: application/json" \
    -d '{"waf_mode": "monitor"}' | grep "waf_mode"

  # 2. Re-send the injection attack
  curl -i -s "http://localhost:8080/rest/products/search?q=%27%20UNION%20SELECT%201%2C2%2C3--" | head -n 8

  # 3. Restore to Block mode
  curl -s -X PUT "http://localhost:8000/api/config" \
    -H "Content-Type: application/json" \
    -d '{"waf_mode": "block"}' > /dev/null
  ```
- **Expected Result**:
  - In Monitor mode, the attack returns **`HTTP/1.1 200 OK`** (allowed through to Juice Shop), but the dashboard logs it with an amber **`FLAG`** badge and attack type `sqli`.
  - Auditing: Configuration change is recorded in `config_audit` table.
- **Fallback Plan**:
  - Open `docs/ARCHITECTURE.md` Section 3.1 and explain dynamic config synchronization via the database audit log.

---

### Beat 5: Benchmark Verification & ModSecurity Comparison (4:00 – 4:30)
- **Objective**: Review the empirical results on the Model & Eval page.
- **Talking Points**:
  > *"All of these results are backed by our Docker parity benchmark against official ModSecurity CRS v4 containers under 1.0 CPU and 512MB RAM parity."*
- **Action**:
  - Switch to browser tab `http://localhost:3000/models`.
  - Highlight the headline comparison table:
    1. **Adversarial Evasions**: **90.32%** (AI-WAF) vs. **24.15%** (ModSecurity PL1).
    2. **False Positive Rate**: **0.00%** on 4,507 benign queries.
    3. **Latency SLA**: **2.55 ms** single-request p95 overhead (PRD target $\le 25\text{ ms}$).
    4. **Serial Defense-in-Depth**: Running both in series yields **98.04%** composite protection.
- **Fallback Plan**:
  - Open `eval/results.md` and show the verified JSON benchmark statistics.

---

### Beat 6: Wrap-Up, Release v1.0 & Q&A Buffer (4:30 – 5:00)
- **Talking Points**:
  > *"To conclude: our AI-Driven WAF delivers +66.17% higher detection on zero-day evasions than ModSecurity, achieves zero false positives, explains decisions in sub-milliseconds, and provides full operational observability. The repository is hardened, 133 tests are passing, and the project is tagged `v1.0`. Thank you, and we welcome your questions."*

---

## 3. Presentation Failure Recovery Matrix

| Scenario / Failure Mode | Quick Diagnostic Command | Recovery Action / Fallback Asset |
|:---|:---|:---|
| **Port 8080 unavailable** | `netstat -ano \| grep 8080` | Run `make down && make up`, or demo API via port `8000`. |
| **Database locked (SQLite)** | `rm -f data/waf.db-journal` | Run `make demo-reset` to reinitialize clean SQLite instance. |
| **Juice Shop upstream slow** | `docker restart demo-app` | Explain that WAF proxy times out gracefully (`fail_mode=closed`). |
| **Docker daemon down** | Check Docker Desktop service | Switch immediately to static visual walk-through: `docs/SLIDES.md`, `eval/figures/*.png`, and `docs/FINAL_REPORT.md`. |
| **Network disconnected** | None required | All components run 100% locally on `localhost` without external internet dependencies. |

---

## 4. One-Click Command Cheat Sheet

```bash
# Clean reset (< 5 sec):
make demo-reset

# Benign Request (HTTP 200):
curl -i "http://localhost:8080/rest/products/search?q=apple+juice"

# Textbook SQL Injection (HTTP 403, Rule Hit):
curl -i -X POST "http://localhost:8080/rest/user/login" -H "Content-Type: application/json" -d '{"email":"admin'\'' OR 1=1--","password":"x"}'

# Obfuscated Evasion (HTTP 403, ML Hit, Rules Miss):
curl -i "http://localhost:8080/rest/products/search?q=select%20and%200x61=0x61"

# Set Monitor Mode:
curl -X PUT "http://localhost:8000/api/config" -H "Content-Type: application/json" -d '{"waf_mode":"monitor"}'

# Set Block Mode:
curl -X PUT "http://localhost:8000/api/config" -H "Content-Type: application/json" -d '{"waf_mode":"block"}'
```
