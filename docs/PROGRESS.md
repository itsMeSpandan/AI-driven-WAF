# AI-Driven Web Application Firewall (WAF) & Analytics Dashboard

# progress.md (Tracker)

> Update the checkboxes and the status table after every work session.

## Overall Status

| Stage | Owner(s) | Status | Target | Notes |
|---|---|---|---|---|
| 1. Foundations & Contracts | All | ✅ Done | Week 1 | Full repo scaffold, proxy, frozen API, Next.js UI, EDA, simulator |
| 2. Detection Core | A, B, C | ✅ Done | Weeks 2–3 | TF-IDF + lexical features, 4 models trained, LogisticRegression selected, 29 bounded rules, gateway integration, tests passing |
| 3. Robustness & Explainability | A, B, C | ⬜ Not started | Weeks 3–4 | Data augmentation, evasion set, cross-dataset eval, SHAP/LIME explainer tokens |
| 4. Dashboard Completion & Controls | C, B, A | ⬜ Not started | Week 5 | Config API, false-positive feedback, rate anomaly flag |
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
- [ ] Augmentation/mutation module (A)
- [ ] Evasion test set (unseen mutation families) (A)
- [ ] Augmented model retrained + compared (A)
- [ ] Cross-dataset evaluation (A)
- [ ] Explainer in gateway (B)
- [ ] Body-size cap (B)
- [ ] Request detail drawer with highlights (C)
- [ ] SSE live feed (C)
- [ ] Shared test: explanations sane on ~30 samples

## Stage 4 — Dashboard Completion & Controls
- [ ] All dashboard panels (C)
- [ ] Settings page (mode, threshold) (C)
- [ ] Model/Eval page (C)
- [ ] Config API (B)
- [ ] Per-IP rate anomaly flag (B)
- [ ] False-positive feedback endpoint + button (B/C)
- [ ] Simple auth on dashboard (B)
- [ ] Retrain-from-feedback script (A)
- [ ] Error analysis of misclassifications (A)
- [ ] Scope freeze declared

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

| Date | Model | Precision | Recall | F1 | FPR | Evasion recall | p95 latency | Notes |
|---|---|---|---|---|---|---|---|---|
| 2026-11-15 | Stage 1 Stub | N/A | N/A | N/A | 0.0% | N/A | 1.68 ms | Gateway overhead baseline |
| 2026-11-15 | LogisticRegression (Winner) | 0.9990 | 1.0000 | 0.9995 | 0.43% | 6.54% (raw CSIC) | 1.39 ms | Calibrated threshold 0.26, size 2.01 MB, rules FPR=0.00% |
| 2026-11-15 | LinearSVM (Calibrated) | 0.9981 | 1.0000 | 0.9990 | 0.85% | 7.91% (raw CSIC) | 2.15 ms | Calibrated threshold 0.16, size 2.77 MB |
| 2026-11-15 | DecisionTree | 1.0000 | 0.9990 | 0.9995 | 0.00% | 0.00% (raw CSIC) | 1.55 ms | Calibrated threshold 0.50, size 1.63 MB |
| 2026-11-15 | RandomForest | 1.0000 | 0.9981 | 0.9990 | 0.00% | 0.38% (raw CSIC) | 36.22 ms | Exceeded 10 ms p95 latency budget |

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
| 2026-11-15 | Dynamic runtime WAF configuration with 1s cache TTL | Enables real-time switching between Monitor and Block modes without database query bottlenecks per proxy request. |
| 2026-11-15 | Fail-safe fallback to rule-only mode | If ML model artefact is missing or corrupt, gateway logs a critical warning and falls back to rule-only mode without crashing. |

## Blockers / Risks Open

| Date | Issue | Owner | Status |
|---|---|---|---|
| 2026-11-15 | SecLists + CSIC 2010 datasets download and preprocessing | A | ✅ Resolved (ingested, canonicalized, split into `train.csv`, `val.csv`, `test.csv`, `cross_source_test.csv`) |
| 2026-11-15 | Cross-source generalization gap on Spanish CSIC anomalous parameter tampering (6.54% recall) | A | Open for Stage 3 (Targeted for Stage 3 data augmentation and evasion training) |
