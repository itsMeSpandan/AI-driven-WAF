# AI-Driven WAF & Real-Time Analytics Dashboard — 5-Minute Demo Kit

This document provides a turnkey, reproducible 5-minute presentation script for course demonstrations, viva evaluations, and technical audits.

---

## 1. Quick Setup & Pre-Flight Checks (< 2 minutes)

Execute these commands before the demo starts:

```bash
# 1. Start all container services (Gateway, Dashboard API, Frontend, Upstream Demo App)
make up

# 2. Seed realistic baseline traffic & attacks
make seed

# 3. Verify health endpoints
curl -s http://localhost:8080/health
curl -s http://localhost:8000/api/health
```

Open these browser tabs in advance:
- **Analytics Dashboard**: `http://localhost:3000`
- **Model Evaluation & Baseline View**: `http://localhost:3000/models`
- **Protected Upstream App**: `http://localhost:8080`

---

## 2. Minute-by-Minute Live Presentation Script

### Minute 0:00 – 1:00: Architecture, Gateway & Pass-Through
- **Talking Point**: *"Traditional signature WAFs struggle with obfuscated payloads, while black-box ML models lack interpretability. We built a hybrid AI-WAF with sub-millisecond character n-gram scoring, explainable token attribution, and dynamic operator controls."*
- **Action**:
  1. Show the **Dashboard Overview** (`http://localhost:3000`). Point out the real-time Traffic vs Threats chart and Mode indicator.
  2. Send clean browsing traffic through the gateway:
     ```bash
     curl -s "http://localhost:8080/rest/products/search?q=apple+juice" -i | head -n 5
     ```
  3. Observe **HTTP 200 OK** in terminal and clean traffic count incrementing on the dashboard.

---

### Minute 1:00 – 2:15: Hybrid Attack Detection & Token Attribution (PRD G1 & G3)
- **Talking Point**: *"Let's test an injection attack. Our gateway normalizes the payload, runs deterministic regex checks, scores with our active ML model, and highlights contributing tokens."*
- **Action**:
  1. Send a textbook SQL injection payload:
     ```bash
     curl -s -X POST "http://localhost:8080/rest/user/login" \
          -H "Content-Type: application/json" \
          -d '{"email":"admin'\'' OR '\''1'\''='\''1","password":"test"}' -i | head -n 5
     ```
  2. Observe **HTTP 403 Forbidden** returned immediately by the gateway.
  3. In the Dashboard Request Log, click on the blocked request to open the **Explanation Drawer**.
  4. Point out the **Red Highlight Spans** isolating `' OR '1'='1`, the matched rule tag (`SQLI-RULE-001`), and the ML confidence score ($1.000$).

---

### Minute 2:15 – 3:30: Adversarial Evasion vs ModSecurity CRS Baseline (PRD G5 & G7)
- **Talking Point**: *"Now let's test zero-day adversarial obfuscation (Family B) that was strictly excluded from model training. How does our model compare against industry-standard ModSecurity with OWASP CRS?"*
- **Action**:
  1. Send an obfuscated SQL payload combining inline SQL comments and URL hex encoding:
     ```bash
     curl -s "http://localhost:8080/rest/products/search?q=1%2F*%2A%2Funion%2F*%2A%2Fselect%2F*%2A%2F1%2C2%2Cpassword" -i | head -n 5
     ```
  2. Observe that AI-WAF blocks the attack (**HTTP 403 Forbidden**).
  3. Show the benchmark comparison data:
     - On unseen Family B evasions, ModSecurity CRS PL1 catches only **24.15%**, whereas AI-WAF catches **90.32%** because sub-word character n-grams capture underlying grammatical fragments that defeat regexes.

---

### Minute 3:30 – 4:15: Analyst Feedback & Safe Retraining Loop (PRD G4 & Stage 4)
- **Talking Point**: *"What happens when a security analyst encounters a benign query mistakenly flagged by an overly sensitive threshold? We provide an audited retraining loop with automated shadow validation."*
- **Action**:
  1. In the Explanation Drawer, click **"Submit Correction"** and mark a sample as False Positive.
  2. Run the audited retrain workflow:
     ```bash
     make retrain-feedback
     ```
  3. Show the terminal output: Candidate model is trained, evaluated against the frozen regression set, and only promoted if $\text{FPR} \le 1.0\%$ and latency $\le 25\text{ ms}$.

---

### Minute 4:15 – 5:00: Benchmarks, Latency Compliance & Wrap-Up
- **Talking Point**: *"All results are mathematically grounded with Wilson 95% confidence intervals and verified under concurrent load."*
- **Action**:
  1. Open `http://localhost:3000/models` and show the **Head-to-Head Benchmark Table**.
  2. Highlight the key verified numbers:
     - **In-Distribution Recall**: **97.94%** (ModSec: 27.48%)
     - **Zero-Day Evasion Recall**: **90.32%** (ModSec: 24.15%)
     - **False Positive Rate**: **0.00%** on 4,507 benign requests [0.00%, 0.12%]
     - **p95 Latency**: **2.55 ms** (comfortably under the 25.0 ms SLA)
     - **Composite Serial Recall**: **98.04%** when combining AI-WAF with ModSec

---

## 3. Visual Reference Screenshots

The following diagrams illustrate the expected UI state during the presentation:

| Screen / Feature | Preview File | Description |
|:---|:---|:---|
| **Live Analytics Dashboard** | `docs/screenshots/dashboard_overview.png` | Traffic vs Threats, Threat breakdown, KPI cards, live feed |
| **Token Attribution Drawer** | `docs/screenshots/explanation_drawer.png` | Red highlight token spans, rule metadata, lexical indicators |
| **Model & Baseline Benchmarking** | `docs/screenshots/model_eval_page.png` | Model Card metrics, Head-to-Head comparative table |

---

## 4. Fallback Instructions (Presentation Insurance)

If live infrastructure encounters unexpected issues during the demo:

1. **Docker Daemon Offline**:
   - Run in local Python standalone mode:
     ```bash
     python -m gateway.main &
     python -m dashboard.api.main &
     npm run dev --prefix dashboard/frontend &
     ```
2. **Port 8080 / 3000 in Use**:
   - Check and release ports:
     ```bash
     netstat -ano | findstr :8080
     ```
3. **Pre-Generated Offline Benchmark Proof**:
   - If live curl cannot reach containers, display the verified benchmark reports:
     - `eval/results.md`
     - `eval/figures/roc_curves.png`
     - `eval/figures/latency_concurrency.png`
