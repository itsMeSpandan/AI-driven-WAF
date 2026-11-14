# AI-Driven Web Application Firewall (WAF) & Analytics Dashboard

# progress.md (Tracker)

> Update the checkboxes and the status table after every work session.

## Overall Status

| Stage | Owner(s) | Status | Target | Notes |
|---|---|---|---|---|
| 1. Foundations & Contracts | All | ⬜ Not started | Week 1 | |
| 2. Detection Core | A, B, C | ⬜ Not started | Weeks 2–3 | |
| 3. Robustness & Explainability | A, B, C | ⬜ Not started | Weeks 3–4 | |
| 4. Dashboard Completion & Controls | C, B, A | ⬜ Not started | Week 5 | |
| 5. Evaluation & Benchmarking | A, B, C | ⬜ Not started | Week 6 | |
| 6. Hardening, Docs & Demo | All | ⬜ Not started | Weeks 7–8 | |

Legend: ⬜ Not started · 🟦 In progress · ✅ Done · ⛔ Blocked

## Completed Before Stage 1 (from progress report)
- [x] Literature review of ML and generative-AI WAF papers
- [x] Review of industry security-analytics dashboard patterns
- [x] Limitations/gaps identified (report Section 4)
- [x] Mitigation goals drafted (report Section 5)

## Stage 1 — Foundations & Contracts
- [ ] Scope + roles agreed
- [ ] GitHub repo + README + branch rules
- [ ] Docker Compose skeleton
- [ ] Datasets shortlisted and downloaded (A)
- [ ] EDA notebook + normalised-request format (A)
- [ ] FastAPI proxy forwards to demo app (B)
- [ ] Event schema defined (B)
- [ ] API contract frozen (C)
- [ ] Next.js scaffold with mock data (C)
- [ ] Demo vulnerable app running (C)
- [ ] "Next Steps" section of report filled

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
| | | | | | | | | |

## Decisions Log

| Date | Decision | Reason |
|---|---|---|
| | | |

## Blockers / Risks Open

| Date | Issue | Owner | Status |
|---|---|---|---|
| | | | |
