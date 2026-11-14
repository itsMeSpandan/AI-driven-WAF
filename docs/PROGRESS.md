# AI-Driven Web Application Firewall (WAF) & Analytics Dashboard

# progress.md (Tracker)

> Update the checkboxes and the status table after every work session.

## Overall Status

| Stage | Owner(s) | Status | Target | Notes |
|---|---|---|---|---|
| 1. Foundations & Contracts | All | ✅ Done | Week 1 | Full repo scaffold, proxy, frozen API, Next.js UI, EDA, simulator |
| 2. Detection Core | A, B, C | ⬜ Not started | Weeks 2–3 | Feature extraction, training 4 models, rule layer, DB wiring |
| 3. Robustness & Explainability | A, B, C | ⬜ Not started | Weeks 3–4 | Data augmentation, evasion set, explainer tokens |
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
- [ ] Preprocessing + feature pipeline (A)
- [ ] 4 models trained and compared (A)
- [ ] Threshold calibrated (A)
- [ ] Model artefacts saved + versioned (A)
- [ ] Rule layer implemented (B)
- [ ] Model loaded in gateway (B)
- [ ] Block / Monitor modes (B)
- [ ] Async DB logging (B)
- [ ] Stats + events endpoints (C)
- [ ] Dashboard wired to real data (C)
- [ ] Shared test: live attack blocked and visible

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

## Decisions Log

| Date | Decision | Reason |
|---|---|---|
| 2026-11-15 | Use OWASP Juice Shop (`bkimminich/juice-shop:v17.1.1`) as demo target | Single self-contained container with modern REST/JSON endpoints; zero MySQL configuration hassle compared to DVWA. |
| 2026-11-15 | Decouple request inspection latency from DB write via async `asyncio.Queue` + worker | Ensures DB locks or latency spikes never delay HTTP traffic or crash the gateway. |
| 2026-11-15 | Share SQLAlchemy models across gateway & dashboard API (`gateway/models.py`) | Single source of truth for DB schema (TRD 2.7) preventing schema drift. |
| 2026-11-15 | Deep normalisation with NFKC, bounded iterative URL unquoting (depth 3), and comment stripping | Eliminates common evasion techniques (`%2527`, fullwidth unicode, `SEL/**/ECT`). |
| 2026-11-15 | Frozen OpenAPI 3.1 schema exported to `docs/openapi.json` | Guarantees frozen API contract per TRD 2.6 before frontend and backend diverge. |
| 2026-11-15 | Safety guard in attack simulator (`demo/attack_simulator.py`) | Hard restriction requiring target to be localhost unless `--i-own-this-target` is passed. |

## Blockers / Risks Open

| Date | Issue | Owner | Status |
|---|---|---|---|
| 2026-11-15 | Candidate datasets download required for Stage 2 training | A | Open (download script ready in `ml/data/download.py`) |
