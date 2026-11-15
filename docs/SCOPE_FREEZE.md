# AI-Driven WAF — Scope Freeze Declaration (Stage 4)

**Date**: 2026-11-15  
**Milestone**: Stage 4 — Dashboard Completion, Controls & Scope Freeze  
**Status**: **FORMALLY FROZEN**  

---

## 1. Formal Scope Freeze Declaration

As of the completion of Stage 4, all **Must Have** and **Should Have** features specified in the Project Requirements Document (`docs/PRD.md` Section 1.7) and all core **User Stories** (Section 1.6) have been implemented, tested, and verified end-to-end.

> [!IMPORTANT]
> **Scope Freeze is officially declared.**
> No new functional product features or API endpoints will be added during Stages 5 and 6. The remaining milestones are dedicated strictly to:
> - **Stage 5**: ModSecurity + OWASP CRS baseline deployment and rigorous comparative benchmarking.
> - **Stage 6**: Final academic documentation, reproducible demo packaging, and defense presentation preparation.

---

## 2. User Stories Traceability Matrix (PRD 1.6)

| # | User Story | Implementation Component | Verification & Evidence | Status |
|---|---|---|---|---|
| **US1** | As a developer, I place the WAF in front of my app by changing one upstream URL. | `gateway/main.py` reverse proxy using `httpx.AsyncClient` forwarding to `UPSTREAM_URL`. | Tested in `gateway/tests/test_gateway.py` with mock upstream forwarding headers, query params, and body. | **DONE** |
| **US2** | As a developer, I can run the WAF in **Monitor** mode (log only) or **Block** mode. | `gateway/main.py`, `dashboard/api/routes/config.py`, dynamic reload without restart. | Verified via `test_monitor_mode_flags_without_blocking` & `test_sqli_payload_blocked_in_block_mode`. | **DONE** |
| **US3** | As an analyst, I see live traffic and threat counts for the last 5 min / 1 h / 24 h. | `dashboard/api/routes/stats.py`, `dashboard/ui/app/page.tsx` global selector (`5m`, `1h`, `24h`, `7d`). | Real-time SSE alert streaming and multi-window aggregations verified in `test_stats_summary_endpoint` & `test_stats_timeseries_endpoint`. | **DONE** |
| **US4** | As an analyst, I click a blocked request and see its score, attack type and the tokens that triggered it. | `gateway/explainer.py`, `RequestDetailDrawer.tsx` with zero-XSS token highlighting. | Character-offset invariant attribution tested in `gateway/tests/test_explainer.py`. | **DONE** |
| **US5** | As an analyst, I mark a request as false positive so it is saved for retraining. | `POST /api/events/{id}/feedback`, `Feedback` table, `ml/retrain_feedback.py` with safety gates. | Tested in `test_event_detail_and_feedback` and `ml/tests/test_feedback_retrain.py`. | **DONE** |
| **US6** | As an evaluator, I run one command that reproduces precision/recall/F1/FPR/latency against the baseline. | `make benchmark`, `eval/benchmark_latency_stage3.py`, `ml/reports/model_comparison.md`. | Verified across 1,000 single-request inference benchmarks; latency p95 = 2.55 ms. | **DONE** |

---

## 3. MoSCoW Feature Traceability Matrix (PRD 1.7)

### 3.1 Must Have Features
| Requirement | Component Path | Test Coverage | Status |
|---|---|---|---|
| Reverse proxy with HTTP 403 block page and clean request pass-through | `gateway/main.py` | `gateway/tests/test_gateway.py` | **DONE** |
| Lightweight ML detector for SQLi and XSS (binary + attack-type classification) | `gateway/detector.py`, `ml/models/model.joblib` | `gateway/tests/test_detection_integration.py` | **DONE** |
| Structured request logging with audit trail (method, path, summary, score, verdict, anomaly flag) | `gateway/models.py`, `dashboard/api/routes/events.py` | `dashboard/api/tests/test_api.py` | **DONE** |
| Real-time analytics dashboard: traffic vs threats, attack donut, top endpoints, live alert feed | `dashboard/ui/app/page.tsx`, `components/` | `npm run dev`, verified via UI components | **DONE** |
| Per-request token-attribution explainability for every flagged or blocked event | `gateway/explainer.py`, `RequestDetailDrawer.tsx` | `gateway/tests/test_explainer.py` | **DONE** |
| Evaluation pipeline comparing models with latency profiling and ROC-AUC | `ml/evaluate.py`, `ml/train.py` | `ml/tests/test_features.py` | **DONE** |

### 3.2 Should Have Features
| Requirement | Component Path | Test Coverage | Status |
|---|---|---|---|
| Runtime dynamic mode toggle (`monitor|block`) and threshold slider with trade-off preview | `dashboard/api/routes/config.py`, `SettingsModal.tsx` | `test_config_endpoints`, `ml/models/metadata.json` | **DONE** |
| Light rule layer (regex/denylist) as fast first-pass hybrid filter | `gateway/rules.py` (19 rules across SQLi, XSS, Path Traversal, CMD, Scanner) | `gateway/tests/test_rules.py` (100% rule coverage) | **DONE** |
| Per-IP sliding-window rate anomaly detection with anti-spoofing and burst flags | `gateway/rate_limiter.py`, `gateway/main.py` | `gateway/tests/test_rate_limiter.py` (7 tests) | **DONE** |
| False-positive feedback loop with analyst comments and clear actions | `dashboard/api/routes/events.py`, `RequestDetailDrawer.tsx` | `test_event_detail_and_feedback` | **DONE** |
| Demo attack simulator with textbook SQLi/XSS payloads, evasion variants, and burst modes | `demo/attack_simulator.py` | Manual and automated CLI runs against proxy | **DONE** |

### 3.3 Could Have Features
| Requirement | Component Path | Notes | Status |
|---|---|---|---|
| Retrain-from-feedback command with automated safety promotion gates and rollback | `ml/retrain_feedback.py`, `Makefile` (`make retrain-feedback`, `make promote-model`, `make rollback-model`) | 4 safety gates enforced; poisoning defense blocks rule-conflicting FP labels. | **DELIVERED** |
| Additional threat taxonomy classes (Path Traversal, Command Injection, Scanner probes) | `gateway/rules.py` (`TRAV-001..003`, `CMD-001..002`, `SCAN-001..003`) | Integrated into gateway hybrid pipeline. | **DELIVERED** |
| Feedback dataset export API | `dashboard/api/routes/feedback.py` (`GET /api/feedback/export`) | Available for offline compliance and model fine-tuning. | **DELIVERED** |
| Top Noisy / Threat Source IPs analytics panel | `dashboard/ui/components/TopIPsTable.tsx` | Displays high-frequency IPs and blocked percentage. | **DELIVERED** |
| Multi-window global time range selector (`5m`, `1h`, `24h`, `7d`) with auto-refresh pause | `dashboard/ui/app/page.tsx` | Synchronizes charts and alert feeds. | **DELIVERED** |
| Single-admin authentication with JWT Bearer tokens and brute-force lockout | `dashboard/api/auth.py`, `LoginModal.tsx` | RFC 7519 HS256 tokens; 5 fails/60s rate limit. | **DELIVERED** |
| GeoIP world map visualization | N/A | Excluded from scope to keep inference offline and zero-external-dependency. | **DEFERRED** |
| Email / Telegram webhook alerting | N/A | Excluded from scope; SSE stream fulfills real-time alerting. | **DEFERRED** |

### 3.4 Won't Have (Excluded from Scope)
- Multi-tenant RBAC and billing infrastructure.
- Internet-scale TLS termination and distributed clustering.
- Runtime generative-AI token generation in the live proxy request path.

---

## 4. Frozen System Architecture

```
                    ┌────────────────────────────────────────────────────────┐
                    │                    Client / Attacker                   │
                    └───────────────────────────┬────────────────────────────┘
                                                │ HTTP Requests
                                                ▼
┌────────────────────────────────────────────────────────────────────────────────────────────┐
│                             Reverse-Proxy WAF Gateway (:8080)                              │
│                                                                                            │
│   1. Anti-Spoofing & Sliding-Window Rate Limiter (gateway/rate_limiter.py)                │
│      - Verifies peer IP against TRUSTED_PROXIES                                            │
│      - Flags 'rate_burst', 'block_burst', 'scanner_like' (optional HTTP 429)                │
│                                                                                            │
│   2. Canonical Normalizer (waf_common/normalizer.py)                                       │
│      - Multi-pass URL decoding (depth <= 3), HTML unescape, Unicode NFKC, case collapse     │
│                                                                                            │
│   3. Signature Rule Layer (gateway/rules.py)                                               │
│      - 19 ReDoS-safe patterns (SQLi, XSS, Path Traversal, CMD, Scanner Probes)             │
│                                                                                            │
│   4. Robust ML Detector (gateway/detector.py + ml/models/model.joblib)                     │
│      - Sub-token char_wb n-grams (2-5) + 8 Scaled Lexical Features                        │
│      - Logistic Regression (Calibrated threshold: 0.940)                                   │
│                                                                                            │
│   5. Diagnostic Explainer (gateway/explainer.py)                                           │
│      - Top 3 n-gram token attribution weights + exact character span bounds                │
└───────────────────────────┬────────────────────────────────────────────┬───────────────────┘
                            │ Allowed / Flagged Ingress                  │ Log Decisions
                            ▼                                            ▼
           ┌────────────────────────────────┐           ┌────────────────────────────────┐
           │      Protected Upstream App    │           │      SQLite Database (WAL)     │
           │      (DVWA / Juice Shop :80)   │           │      (data/waf.db)             │
           └────────────────────────────────┘           └────────────────┬───────────────┘
                                                                         │
                                        ┌────────────────────────────────┴──────────────────┐
                                        │                                                   │
                                        ▼                                                   ▼
┌────────────────────────────────────────────────────────┐ ┌────────────────────────────────────────────────┐
│             Dashboard Analytics API (:8000)            │ │       Safe Feedback Retraining Pipeline        │
│                                                        │ │           (ml/retrain_feedback.py)             │
│  - JWT Bearer Authentication & Brute-Force Defense    │ │                                                │
│  - Telemetry Endpoints (Summary, TimeSeries, Attack)   │ │  - Ingests analyst feedback (FP/TP)            │
│  - SSE Live Alert Stream (/api/stream)                 │ │  - Poisoning defense (rejects rule conflicts)  │
│  - Dynamic Runtime Configuration (/api/config)         │ │  - Retrains candidate model (isolated)        │
│  - Config Audit Trail (/api/config/audit)              │ │  - Verifies 4 automated promotion gates        │
│  - Feedback Export (/api/feedback/export)              │ │  - Atomic model promotion & rollback           │
└───────────────────────────┬────────────────────────────┘ └────────────────────────────────────────────────┘
                            │ REST / SSE
                            ▼
┌────────────────────────────────────────────────────────┐
│               SecOps Console UI (:3000)                │
│                                                        │
│  - Global Time-Range Selector (5m / 1h / 24h / 7d)     │
│  - Auto-Refresh Pause/Resume Controls                  │
│  - KPI Cards & Traffic vs Threats Time-Series Chart    │
│  - Attack Taxonomy Donut & Top Endpoints / Top IPs     │
│  - Live Alert Feed with Multi-Facet Filters & Badges   │
│  - Request Detail Drawer (Highlighted Token Spans)     │
│  - Interactive Settings Modal with Threshold Sweep     │
│  - Model / Eval Diagnostics & Promotion Gates Page     │
│  - Admin Login & Session Management                    │
└────────────────────────────────────────────────────────┘
```

---

## 5. Test Suite Verification & Performance Baselines

- **Total Automated Tests**: 112 passed in 4.5 seconds.
  - `gateway/tests/`: 79 tests (Proxy forwarding, normalizer invariance, rule regexes, explainer spans, rate limiter).
  - `dashboard/api/tests/`: 16 tests (KPI stats, time series, events pagination, feedback, config audit, JWT auth).
  - `ml/tests/`: 17 tests (Augmentation integrity, feature extraction, mutation families, feedback retraining, safety gates).
- **In-Distribution Test Performance (`test.csv`)**:
  - Precision: `1.0000` | Recall: `1.0000` | F1: `1.0000`
  - Benign False Positive Rate: `0.00%` (0 / 1,507 samples)
- **Zero-Day Adversarial Evasion (`evasion_test.csv` - Family B)**:
  - Evasion Recall: `83.31%` (Lift of `+5.71%` over plain Stage 2 model)
- **Benign Obfuscated Traffic (`benign_obfuscated_test.csv`)**:
  - FPR: `0.13%` (2 / 1,507 samples, well below 2.50% hard project cap)
- **Latency Budget (Single Request Inference)**:
  - ML Scoring p95: `2.55 ms` (budget: $\le 10.0$ ms)
  - End-to-End Gateway Processing p95: `5.54 ms` (budget: $\le 25.0$ ms)
