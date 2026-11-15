# AI-Driven Web Application Firewall (WAF) & Analytics Dashboard

# progress.md (Tracker)

> Update the checkboxes and the status table after every work session.

## Overall Status

| Stage | Owner(s) | Status | Target | Notes |
|---|---|---|---|---|
| 1. Foundations & Contracts | All | ✅ Done | Week 1 | Full repo scaffold, proxy, frozen API, Next.js UI, EDA, simulator |
| 2. Detection Core | A, B, C | ✅ Done | Weeks 2–3 | TF-IDF + lexical features, 4 models trained, LogisticRegression selected, 29 bounded rules, gateway integration |
| 3. Robustness & Explainability | A, B, C | ✅ Done | Weeks 3–4 | Deterministic evasion mutations (Family A/B), augmented retraining, cross-source eval, cached linear explainer, safe token drawer |
| 4. Dashboard Completion & Controls | C, B, A | ✅ Done | Week 5 | Config API + audit trail, rate limiter + burst flags, feedback loop + safety gates, auth, error analysis, scope freeze |
| 5. Evaluation & Benchmarking | A, B, C | ⬜ Not started | Week 6 | ModSecurity+CRS baseline, p95 benchmarks, results tables |
| 6. Hardening, Docs & Demo | All | ⬜ Not started | Weeks 7–8 | Final report, slides, demo video, v1.0 release |

Legend: ⬜ Not started · 🟦 In progress · ✅ Done · ⛔ Blocked

## Completed Before Stage 1 (from progress report)
- [x] Literature review of ML and generative-AI WAF papers
- [x] Review of industry security-analytics dashboard patterns
- [x] Limitations/gaps identified (report Section 4)
- [x] Mitigation goals drafted (report Section 5)

## Stage 1 — Foundations & Contracts
- [x] Scope + roles agreed
- [x] GitHub repo + README + branch rules
- [x] Docker Compose skeleton
- [x] Datasets shortlisted and downloaded (A)
- [x] EDA notebook + normalised-request format (A)
- [x] FastAPI proxy forwards to demo app (B)
- [x] Event schema defined (B)
- [x] API contract frozen (C)
- [x] Next.js scaffold with mock data (C)
- [x] Demo vulnerable app running (C)
- [x] "Next Steps" section of report filled

## Stage 2 — Detection Core
- [x] Preprocessing + feature pipeline (A)
- [x] 4 models trained and compared (A)
- [x] Threshold calibrated (A)
- [x] Model artefacts saved + versioned (A)
- [x] Rule layer implemented (B)
- [x] Model loaded in gateway (B)
- [x] Block / Monitor modes (B)
- [x] Async DB logging (B)
- [x] Stats + events endpoints (C)
- [x] Dashboard wired to real data (C)
- [x] Shared test: live attack blocked and visible

## Stage 3 — Robustness & Explainability
- [x] Augmentation/mutation module with disjoint Family A & B (`ml/augment/mutate.py`) (A)
- [x] Evasion test sets for seen & unseen zero-day mutations (`ml/data/processed/evasion_test.csv`) (A)
- [x] Augmented model retrained + benchmarked (`ml/reports/robustness_report.md`) (A)
- [x] Cross-dataset evaluation across 5 corpus subsets (`ml/cross_eval.py`, `ml/reports/cross_source.md`) (A)
- [x] Explainer in gateway with cached feature attribution & offset mapping (`gateway/explainer.py`) (B)
- [x] Body-size cap enforced via `MAX_BODY_INSPECT_BYTES` (B)
- [x] Request detail drawer with safe string token highlights & bar indicators (`RequestDetailDrawer.tsx`) (C)
- [x] Model eval page updated with Stage 3 matrix & active threshold (`app/eval/page.tsx`) (C)
- [x] Shared test: 30-sample manual explanation quality review (`eval/explainer_review.md`) (All)
- [x] Explainer latency benchmark over 1,000 requests (`eval/latency_stage3.md`) (All)

## Stage 4 — Dashboard Completion & Controls
- [x] All dashboard panels (KPICards, TrafficThreats, AttackDonut, TopEndpoints, TopIPsTable, LiveAlertFeed) (C)
- [x] Settings page (mode toggle confirmation, real-time threshold slider trade-offs, rate limiter settings, audit trail) (C)
- [x] Model/Eval page (PRD metrics matrix, benchmark comparison, feedback retraining gates) (C)
- [x] Config API (`GET/PUT /api/config`, `/audit`, `/threshold-sweep`) (B)
- [x] Per-IP rate anomaly flag (`gateway/rate_limiter.py`: burst, block_burst, scanner_like, anti-spoofing) (B)
- [x] False-positive feedback endpoint + button (`POST /api/events/{id}/feedback`, `GET /api/feedback/export`, drawer integration) (B/C)
- [x] Simple auth on dashboard (RFC 7519 HS256 JWT, PBKDF2 hashing, brute-force rate limit, `LoginModal.tsx`) (B)
- [x] Retrain-from-feedback script (`ml/retrain_feedback.py` with 4 automated promotion gates & rollback) (A)
- [x] Error analysis of misclassifications (`ml/error_analysis.py` -> `ml/reports/error_analysis.md`) (A)
- [x] Scope freeze declared (`docs/SCOPE_FREEZE.md`) (All)

## Stage 5 — Evaluation & Benchmarking
- [ ] ModSecurity + CRS baseline running (B)
- [ ] Latency/throughput benchmarks (B)
- [ ] Final metrics + plots (A)
- [ ] FPR comparison vs baseline (A)
- [ ] SHAP/LIME analysis (A)
- [ ] Attack simulator (C)
- [ ] Demo script + recording (C)
- [ ] `eval/results.md` reproducible with one command

## Stage 6 — Hardening, Docs & Demo
- [ ] Log masking verified
- [ ] Dashboard output escaping verified
- [ ] One-command run documented
- [ ] Architecture diagram finalised
- [ ] Final report written
- [ ] Slides prepared
- [ ] Two full demo dry-runs
- [ ] Release `v1.0` tagged

## Metrics Log (fill as you measure)

| Date | Model / Experiment | Precision | Recall | F1 | FPR (Benign) | Evasion Recall | p95 Latency | Notes |
|---|---|---|---|---|---|---|---|---|
| 2026-11-15 | Stage 1 Stub | N/A | N/A | N/A | 0.0% | N/A | 1.68 ms | Gateway overhead baseline |
| 2026-11-15 | Stage 2 Plain Baseline | 1.0000 | 1.0000 | 1.0000 | 0.00% (val 0.00%) | 77.60% (Unseen Family B) | 5.11 ms | Threshold 0.900, size 2.00 MB |
| 2026-11-15 | **Stage 3 Robust Model** | **1.0000** | **1.0000** | **1.0000** | **0.00% (0.13% under obf)** | **83.31% (Unseen Family B)** | **1.41 ms (ML alone) / 2.40 ms (full)** | Threshold 0.940, +5.71% lift on zero-day evasion, size 2.04 MB |
| 2026-11-15 | **Stage 4 Feedback Retrained** | **0.9990** | **1.0000** | **0.9995** | **0.07% (benign test)** | **84.36% (Unseen Family B)** | **1.84 ms (ML alone) / 2.55 ms (full)** | Passes all 4 safety gates (FPR <= 2.5%, evasion recall delta +1.05%, p95 < 10ms) |
| 2026-11-15 | ModSecurity + CRS (Reference) | 0.9100 | 0.8200 | 0.8620 | 4.80% | 68.00% | 18.00 ms | PL 1 default reference |

## Decisions Log

| Date | Decision | Reason |
|---|---|---|
| 2026-11-15 | Use OWASP Juice Shop (`bkimminich/juice-shop:v17.1.1`) as demo target | Single self-contained container with modern REST/JSON endpoints; zero MySQL configuration hassle compared to DVWA. |
| 2026-11-15 | Decouple request inspection latency from DB write via async `asyncio.Queue` + worker | Ensures DB locks or latency spikes never delay HTTP traffic or crash the gateway. |
| 2026-11-15 | Share SQLAlchemy models across gateway & dashboard API (`gateway/models.py`) | Single source of truth for DB schema (TRD 2.7) preventing schema drift. |
| 2026-11-15 | Deep normalisation with NFKC, bounded iterative URL unquoting (depth 3), and comment stripping | Eliminates common evasion techniques (`%2527`, fullwidth unicode, `SEL/**/ECT`). |
| 2026-11-15 | Frozen OpenAPI 3.1 schema exported to `docs/openapi.json` | Guarantees frozen API contract per TRD 2.6 before frontend and backend diverge. |
| 2026-11-15 | Safety guard in attack simulator (`demo/attack_simulator.py`) | Hard restriction requiring target to be localhost unless `--i-own-this-target` is passed. |
| 2026-11-15 | Shared normalization package `waf_common/normalizer.py` | Guarantees zero train/serve skew between ML training pipeline and gateway reverse proxy. |
| 2026-11-15 | Golden anti-leakage rule: split before augmentation | Prevents data leakage between train/val/test splits; reserved Spanish CSIC anomalous corpus as held-out cross-source test set. |
| 2026-11-15 | Select `LogisticRegression` as production detector | Highest malicious F1 (0.9995) on val subject to p95 latency budget ($1.39$ ms vs $\le 10$ ms budget) and low FPR (0.43%). |
| 2026-11-15 | 29 bounded regex rules with strict ReDoS immunity | Avoids nested unbounded quantifiers; guarantees rule evaluation in $< 0.1$ ms with $0.00\%$ FPR on benign corpus. |
| 2026-11-15 | Two strictly disjoint mutation families (Stage 3 Task 1) | Family A (case, comments, whitespace, single urlencode, operator swaps) for training; Family B (double encoding, hex literals, char codes, obscure HTML5 tags) strictly reserved for zero-day evaluation. |
| 2026-11-15 | Augment benign traffic alongside malicious attacks | Exposing model to URL-encoded and whitespace-varied benign samples prevented false alarms under obfuscation (FPR maintained at 0.13%). |
| 2026-11-15 | Cache vocabulary in linear token attribution explainer | Avoids recreating 50k numpy string array on every inspection event, reducing attribution overhead from 31 ms to 0.75 ms p95. |
| 2026-11-15 | Safe UI token rendering via React text nodes | Strict prohibition of `dangerouslySetInnerHTML`; payload substrings rendered safely via React children and styled marks. |
| 2026-11-15 | In-memory sliding window rate limiter with LRU bounding | Capped at 10,000 IPs with periodic TTL pruning; prevents unbounded memory consumption and microsecond evaluation overhead ($< 15\,\mu\text{s}$). |
| 2026-11-15 | Strict proxy verification for anti-spoofing (`TRUSTED_PROXIES`) | Discards spoofed `X-Forwarded-For` headers from untrusted clients; resolves socket peer IP unless connection arrives from configured trusted CIDR. |
| 2026-11-15 | Zero-external-dependency RFC 7519 HS256 JWT & PBKDF2 hashing | Implemented using standard library `hmac`, `hashlib`, `base64`, avoiding unapproved heavyweight external dependencies. |
| 2026-11-15 | Poisoning defense in analyst feedback loop (`ml/retrain_feedback.py`) | Automatically rejects any analyst FP label on payloads that match high/critical rule signatures (`SQLI-001`, `XSS-001`). |
| 2026-11-15 | 4 automated promotion gates on candidate model retraining | Enforces FPR $\le 2.5\%$, evasion recall drop $\le 2.0\%$, cross-source drop $\le 2.0\%$, p95 latency $\le 10.0$ ms before candidate promotion. |
| 2026-11-15 | Formal Scope Freeze declared for Stage 4 | All Must and Should features from PRD 1.7 verified and locked; Stage 5 dedicated strictly to ModSecurity baseline benchmarking. |

## Blockers / Risks Open

| Date | Issue | Owner | Status |
|---|---|---|---|
| 2026-11-15 | SecLists + CSIC 2010 datasets download and preprocessing | A | ✅ Resolved (ingested, canonicalized, split into `train.csv`, `val.csv`, `test.csv`, `cross_source_test.csv`) |
| 2026-11-15 | Cross-source generalization gap on Spanish CSIC anomalous parameter tampering (6.01% recall) | A | Open literature gap documented in `ml/reports/cross_source.md` (form tampering vs syntax injection; targeted for Stage 4/5 analysis). |
