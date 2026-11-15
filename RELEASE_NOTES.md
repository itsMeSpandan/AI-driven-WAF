# Release Notes — AI-Driven WAF & Real-Time Analytics Dashboard (v1.0.0)

**Release Version**: `v1.0.0` (Tagged locally as `v1.0`)  
**Release Date**: November 15, 2026  
**License**: MIT License  
**Codebase Stability**: Production Hardened / Scope Frozen (`docs/SCOPE_FREEZE.md`)

---

## 1. Executive Summary

We are pleased to announce the release of **v1.0.0** of the **AI-Driven Web Application Firewall (WAF) & Real-Time Analytics Dashboard**. This release delivers an end-to-end, high-performance defensive reverse proxy combining deterministic signature denylisting with a regularized machine learning detector (`LogisticRegression_Augmented`) utilizing sub-word character n-grams and dense lexical markers.

Evaluated under strict Docker hardware parity (1.0 CPU, 512MB RAM) against official ModSecurity Core Rule Set (CRS v4.8.0), our hybrid pipeline achieves **90.32% recall** on unseen zero-day adversarial evasions (compared to **24.15%** for ModSecurity PL1), maintains **0.00% False Positive Rate** across 4,507 benign queries, and adds single-request p95 latency overhead of just **2.55 ms**. Running both engines in series provides **90.43% to 98.04%** composite defense-in-depth.

---

## 2. Key Headline Benchmarks

All metrics derived from automated evaluations with Wilson 95% Confidence Intervals:

| Evaluation Partition | Evaluation Size ($N$) | AI-WAF Hybrid | ModSecurity PL1 | Delta ($\Delta$) | PRD Target | Status |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| **In-Distribution Test (G1)** | 2,526 | **97.94%** [96.9–98.7%] | 27.48% [24.8–30.3%] | **+70.46%** | $\ge 90.0\%$ | ✅ **MET** |
| **Unseen Family B Evasion (G5)** | 857 | **90.32%** [88.1–92.1%] | 24.15% [21.4–27.1%] | **+66.17%** | $\ge 75.0\%$ | ✅ **MET** |
| **False Positive Rate (G2)** | 4,507 | **0.00%** [0.00–0.12%] | 0.00% [0.00–0.12%] | **Parity** | $\le 1.0\%$ | ✅ **MET** |
| **Token Explainability Coverage (G3)** | 100% blocks | **100.0%** (< 1.0 ms) | 0.0% (Regex ID only) | **+100.0%** | 100% | ✅ **MET** |
| **Inspection Latency Overhead (G4)** | Single Request | **2.55 ms** p95 | 4.00 ms p95 | **-1.45 ms** | $\le 25.0\text{ ms}$ | ✅ **MET** |
| **Serial Composite Recall** | In-Distribution | **98.04%** | 27.48% | **+70.56%** | Baseline | ✅ **MET** |

---

## 3. System Components & Architecture

The release artifacts include four containerized services orchestrated via Docker Compose:

1. **WAF Gateway Proxy (`gateway/`)**:
   - Asynchronous reverse proxy (FastAPI + `httpx`) on port `8080`.
   - Multi-pass iterative canonicalizer (`waf_common/normalizer.py`): URL unquoting, NFKC Unicode standardisation, SQL inline comment collapse.
   - Deterministic Rule Engine: 29 ReDoS-immune regex signatures (`gateway/rules.py`).
   - ML Detector: L2-regularized Logistic Regression ($C=5.0$) on 20,000 sub-word 3-5 character n-grams + 8 dense lexical markers (`gateway/detector.py`).
   - Cached Linear Token Explainer: Mathematically equivalent to exact Shapley values under high feature sparsity (< 1.0 ms latency).
   - In-memory sliding-window rate limiter with LRU eviction and anti-spoofing proxy validation.
2. **Dashboard Backend API (`dashboard/api/`)**:
   - REST endpoints and Server-Sent Events (SSE) telemetry on port `8000`.
   - Hardened with Content Security Policy, strict origin whitelisting, and generic 500 error masking.
   - Dynamic runtime configuration synchronization via `Config` database table and audit log.
3. **SecOps Analytics UI (`dashboard/ui/`)**:
   - Next.js 14 console on port `3000` with dark-mode Tailwind UI.
   - Live Traffic vs Threats charts, attack-type distributions, and interactive explanation drawers.
   - Model & Evaluation view (`/models`) rendering real-time benchmark matrices against ModSecurity.
4. **Isolated Upstream Target (`demo-app`)**:
   - Containerized OWASP Juice Shop (`v17.1.1`) isolated inside the Docker network with zero host ports exposed.

---

## 4. Quickstart: 5 Commands to Run

### System Requirements
- **OS**: Linux (Ubuntu 22.04+), macOS (Apple Silicon or Intel), or Windows 11 (with WSL2 or Docker Desktop).
- **Runtimes**: Docker 24+ & Docker Compose v2; Python 3.10+ (for local CLI/ML tooling); Node.js 18+ (for local UI development).
- **Hardware**: Minimum 2 CPU cores, 4 GB RAM.

### 5-Step Startup Sequence
```bash
# 1. Clone repository
git clone https://github.com/mini-project/ai-waf.git
cd ai-waf

# 2. Copy production environment configuration
cp .env.example .env

# 3. Start containerized services (Gateway, Dashboard API, Frontend, Juice Shop)
make up

# 4. Initialize clean demo state (seeds 50 baseline events in < 1 second)
make demo-reset

# 5. Open SecOps Console in browser
# http://localhost:3000
```

---

## 5. Security & Sanitisation Highlights

- **ISO/IEC 7812 Luhn Checksum Redaction**: Automatically verifies and redacts credit card sequences (`[REDACTED_CC]`).
- **Pattern-Based Credential Masking**: Redacts JWTs, Bearer tokens, API keys, and Canary secrets across query summaries, body summaries, and canonical text strings.
- **Canary Leakage Verification**: 4 permanent integration tests (`gateway/tests/test_canary_leakage.py`) prove zero planted secrets leak into SQLite or log streams.
- **Defensive Retraining Gates**: Safe analyst retraining loop with anti-poisoning signature protection and 4 automated promotion gates (FPR $\le 2.5\%$, Evasion drop $\le 2\%$, Cross-source drop $\le 2\%$, Latency $\le 10\text{ ms}$).

---

## 6. Known Limitations

1. **Extreme Out-of-Distribution Domain Shift**: On the Spanish CSIC 2010 eCommerce corpus, pure ML recall dropped to 1.18% due to unfamiliar path tokens. The hybrid rule layer provides the essential safety net (20.29% composite recall).
2. **Python GIL Throughput Bounds**: Under multithreaded ML scoring, the Python proxy sustains ~619 RPS, compared to > 29,000 RPS for ModSecurity compiled as a C module. Recommended for serial deployment behind high-throughput load balancers.
3. **Body Inspection Window**: Large request bodies exceeding 16KB are inspected only on the leading 16,384 bytes to mitigate ReDoS and buffer exhaustion attacks.
4. **SQLite Multi-Writer Concurrency**: The default local storage uses SQLite in WAL mode; for high-concurrency production deployments, configure `DB_URL` with PostgreSQL.

---

## 7. Verification & Release Artifacts

- **Model Artifact**: `ml/models/model.joblib` (2.00 MB, tracked directly in git).
- **Test Suite**: 133 unit and contract tests passing (`pytest -v`).
- **Documentation**:
  - `docs/FINAL_REPORT.md` & `docs/FINAL_REPORT.docx`: 14-section comprehensive academic report.
  - `docs/ARCHITECTURE.md`: Complete component, sequence, and ER diagrams.
  - `docs/SECURITY_AUDIT.md`: Audited findings and remediation logs.
  - `docs/SLIDES.md`: 12-slide presentation outline with speaker notes.
  - `docs/DEMO.md`: Timed 5-minute live demonstration script.
  - `docs/DEMO_DRYRUN.md`: Automated dry run verification log (100% pass rate).
