# Changelog

All notable changes to the **AI-Driven WAF & Real-Time Analytics Dashboard** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-11-15

### UI Revamp — "Monolith" Light Theme
- Restyled dashboard UI to high-contrast, black-and-grey, zero-radius "Monolith" specification:
  - Designed monochrome navigation bar, 5 KPI tiles with inverted Blocked tile, and sharp panel borders.
  - Replaced donut chart with a 100% stacked horizontal attack breakdown bar.
  - Implemented IBM Plex Sans and IBM Plex Mono typography loaded via `next/font`.
  - Authored `docs/UI_STYLE_GUIDE.md` defining design tokens and strict chart palette mappings.

### Stage 6 — Hardening, Docs & Demo (Release v1.0)
#### Added
- **Production Masking & Redaction**:
  - Implemented ISO/IEC 7812 Luhn checksum validator (`luhn_check`) in `gateway/masking.py` redacting valid credit cards as `[REDACTED_CC]`.
  - Added regex pattern redaction for JWTs (`[REDACTED_JWT]`), Bearer tokens (`Bearer [REDACTED_TOKEN]`), and Canary test secrets (`[REDACTED_CANARY]`).
  - Added recursive dictionary/list JSON masking and pre-storage canonical text sanitization to close data leakage sinks.
- **Security Hardening**:
  - Integrated `SecurityHeadersMiddleware` on Dashboard API enforcing `Content-Security-Policy: frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, and `ALLOWED_ORIGINS` CORS origin whitelist.
  - Added global 500 internal server error handler intercepting uncaught exceptions without leaking server stack traces.
  - Isolated OWASP Juice Shop (`demo-app`) from host port exposure (`3001`), ensuring it is reachable exclusively via the WAF proxy network.
  - Authored comprehensive `docs/SECURITY_AUDIT.md` logging 6 findings (2 High, 3 Medium, 1 Low), all remediated.
- **Security & Canary Leakage Test Suites**:
  - Added `gateway/tests/test_canary_leakage.py` (4 tests proving zero secrets leak into logs or databases).
  - Added `dashboard/api/tests/test_security_headers.py` (3 tests verifying CSP, CORS, and generic 500 error sanitization).
- **Architecture Documentation & Diagrams**:
  - Authored `docs/ARCHITECTURE.md` documenting end-to-end component interactions, data flows, database schemas, and TRD variance rationale.
  - Added automated matplotlib diagram generator `docs/diagrams/generate_diagrams.py` exporting `system_architecture.png`, `request_lifecycle.png`, and `model_lifecycle.png`.
- **Academic Final Report**:
  - Authored complete 14-section academic report `docs/FINAL_REPORT.md` featuring literature review, mathematical Shapley equivalence proofs, empirical benchmark tables, and failure analyses.
  - Created automated Word document generator `docs/export_docx.py` generating `docs/FINAL_REPORT.docx` (641 KB) with embedded figures and tables.
- **Turnkey Demo Kit & Automated Dry Runs**:
  - Created turnkey database reset script `scripts/demo_reset.py` and `make demo-reset` target (< 1 sec execution).
  - Authored timed 5-minute presentation script `docs/DEMO.md` with visual fallbacks for all presentation beats.
  - Authored 12-slide presentation outline with speaker notes `docs/SLIDES.md`.
  - Created `docs/demo_dryrun.py` executing two automated dry runs recorded in `docs/DEMO_DRYRUN.md` (100% pass rate).
- **Packaging & Tracking**:
  - Tracked active model weights `ml/models/model.joblib` (2.00 MB) in git for out-of-the-box fresh clone reproduction.
  - Added `docs/KNOWN_ISSUES.md`, `RELEASE_NOTES.md`, and `THIRD_PARTY.md`.

---

## [0.5.0] - 2026-11-15

### Stage 5 — Evaluation & Benchmarking
#### Added
- **Baseline Container Parity**:
  - Pinned official OWASP Core Rule Set Apache container (`owasp/modsecurity-crs:4.8.0-apache`) with identical CPU and memory parity (1.0 CPU, 512MB RAM).
  - Developed `eval/smoke_baseline.py` and `eval/benchmark_dual_proxy.py` to replay raw HTTP requests simultaneously across AI-WAF and ModSecurity proxies.
- **Six Standard Evaluation Corpora (`eval/corpora/`)**:
  - In-Distribution Test (2,526 requests).
  - Family A Evasion (Seen mutations: 1,019 requests).
  - Family B Evasion (Strictly held-out zero-day: 857 requests).
  - CSIC 2010 Out-of-Distribution (12,069 requests).
  - Neutral Independent Benchmark (1,000 requests).
  - Large Benign Corpus (3,000 eCommerce queries).
- **Latency & Concurrency Benchmarking**:
  - Developed `eval/benchmark_perf.py` testing sustained RPS and p50/p95 latency across 10, 50, and 100 concurrent clients.
- **SHAP vs. Linear Explainer Fidelity Study**:
  - Authored `eval/shap_analysis.py` proving 80.0% feature alignment between exact KernelSHAP and sub-millisecond linear attribution $w_i x_i$.
- **Automated Figure Generation**:
  - Developed `eval/generate_figures.py` rendering `eval/figures/confusion_matrices.png` and `eval/figures/latency_concurrency.png`.
- **Results Documentation**:
  - Exported verified JSON and Markdown evaluation results in `eval/results/detection.json`, `eval/results/performance.json`, and `eval/results.md`.

---

## [0.4.0] - 2026-11-14

### Stage 4 — Dashboard Completion & Controls (Scope Freeze)
#### Added
- **Scope Freeze Declaration**:
  - Formally locked all Must and Should requirements under `docs/SCOPE_FREEZE.md`.
- **SecOps Dashboard Pages & Components**:
  - Live Overview page with Server-Sent Events (SSE) streaming telemetry.
  - Paginated Request Log with filtering by verdict, attack type, and IP.
  - Interactive Request Detail Drawer displaying highlighted attack token spans.
  - Model & Evaluation page (`/models`) rendering head-to-head metrics and PRD target comparisons.
  - Dynamic Settings page (`/settings`) supporting live mode toggles (Block vs Monitor) and ML threshold adjustment.
- **Analyst Retraining Pipeline**:
  - Implemented `ml/retrain_feedback.py` with anti-poisoning signature filter and four automated quality promotion gates (FPR $\le 2.5\%$, Evasion recall drop $\le 2\%$, Cross-source drop $\le 2\%$, Latency $\le 10\text{ ms}$).
  - Added atomic rollback command `make rollback-model`.
- **Sliding-Window Rate Limiter**:
  - Implemented `gateway/rate_limiter.py` with LRU IP eviction, burst penalty escalation, scanner detection, and anti-spoofing proxy validation.

---

## [0.3.0] - 2026-11-14

### Stage 3 — Robustness & Explainability
#### Added
- **Adversarial Training Augmentation**:
  - Implemented `ml/augment.py` generating Family A syntactic mutations (case folding, inline comments, whitespace manipulation, operator substitution).
  - Augmented dataset from 4,000 to 16,824 samples, boosting zero-day evasion recall from 77.6% to 89.85%.
- **Linear Feature Attribution Explainer**:
  - Implemented sub-millisecond explainer in `gateway/explainer.py` mapping non-zero TF-IDF feature weights directly to character byte spans.
- **Held-Out Family B Evasion Dataset**:
  - Curated 857 held-out zero-day mutations (hex literals, double encoding, `String.fromCharCode`) strictly excluded from training.
- **Model Card & Comparison**:
  - Created `docs/MODEL_CARD.md` documenting model architecture, training hyperparameters, limitations, and intended use.

---

## [0.2.0] - 2026-11-14

### Stage 2 — Detection Core
#### Added
- **Dataset Assembly**:
  - Implemented `ml/data/download.py` and `ml/prepare.py` collecting PayloadsAllTheThings, SecLists, and CSIC 2010 datasets.
- **Feature Engineering & ML Training**:
  - Implemented `FeatureUnion` combining 20,000 TF-IDF sub-word character 3-5 n-grams and 8 dense lexical markers.
  - Trained L2-regularized Logistic Regression classifier and calibrated decision threshold to $\tau = 0.940$.
- **Deterministic Rule Engine**:
  - Implemented 29 ReDoS-immune regular expression signatures in `gateway/rules.py` covering SQLi, XSS, Path Traversal, and sensitive probes.
- **Consensus Decision Pipeline**:
  - Built `gateway/pipeline.py` uniting rules, ML scoring, and threshold evaluation.

---

## [0.1.0] - 2026-11-14

### Stage 1 — Scaffold, Gateway & Initial Dashboard
#### Added
- **Monorepo Architecture**:
  - Docker Compose orchestration for WAF Gateway, Dashboard API, Next.js UI, and OWASP Juice Shop.
- **Async Gateway Proxy**:
  - FastAPI reverse proxy with `httpx` async forwarding, hop-by-hop header stripping, and async queue logging.
- **Database Schema**:
  - SQLAlchemy models for `Event`, `Config`, `ConfigAudit`, `Feedback`, and `ModelVersion`.
- **Initial Normalization**:
  - Unicode NFKC folding, recursive URL unquoting, and SQL comment stripping in `waf_common/normalizer.py`.
- **Attack Simulator**:
  - Developed `demo/attack_simulator.py` to replay baseline traffic against the local gateway.
