# AI-Driven Web Application Firewall (WAF) & Analytics Dashboard

# STAGES (Execution Plan, 3 members)

Roles: **A = ML/Data**, **B = Gateway/Backend**, **C = Dashboard/Frontend + Demo**. Testing is shared across everyone in every stage; GitHub repo with README is created in Stage 1 and updated continuously.

## Stage 1 — Foundations & Contracts (Week 1)
**Goal:** Everyone can work in parallel.
- All: finalise scope, create repo, branching rules, `docker-compose` skeleton, fill the blank "Next Steps" in the progress report.
- A: shortlist datasets, download, EDA notebook, define normalised-request format.
- B: FastAPI proxy skeleton forwarding to demo app; define event schema.
- C: freeze API contract (2.6), Next.js scaffold with mock data; bring up DVWA/Juice Shop.
- **Exit:** proxy forwards traffic; mock dashboard renders; datasets chosen.

## Stage 2 — Detection Core (Weeks 2–3)
**Goal:** A working model + rule layer in the gateway.
- A: preprocessing, feature extraction, train/compare 4 models, threshold calibration, save artefacts.
- B: rule layer, model loader, block/monitor modes, async logging to DB.
- C: DB-backed `/api/stats/*` and `/api/events` endpoints; wire dashboard to real data.
- **Exit:** malicious sample blocked live; event visible in DB and dashboard table.

## Stage 3 — Robustness & Explainability (Weeks 3–4)
**Goal:** Address the literature gaps (G3, G5, G6).
- A: augmentation/mutation module, evasion test set, retrain augmented model, cross-dataset evaluation.
- B: explainer integration returning top tokens + matched rule; request-size cap.
- C: request-detail drawer with highlighted tokens; SSE live feed.
- **Exit:** every flagged request has an explanation; robustness comparison table produced.

## Stage 4 — Dashboard Completion & Controls (Week 5)
**Goal:** Feature-complete (scope freeze).
- C: all panels, settings (mode/threshold), model/eval page, UI polish.
- B: config API, per-IP rate anomaly flag, false-positive feedback endpoint, simple auth.
- A: retrain-from-feedback script (should-have), error analysis on misclassified samples.
- **Exit:** all Must + Should features demoable.

## Stage 5 — Evaluation & Benchmarking (Week 6)
**Goal:** Evidence for the report.
- B: ModSecurity+CRS baseline setup; latency/throughput benchmarks.
- A: final metrics, plots, SHAP report, FPR comparison vs baseline.
- C: attack simulator, demo script, screenshots/screen recording.
- **Exit:** `eval/results.md` with all tables; numbers reproducible by one command.

## Stage 6 — Hardening, Docs & Demo (Weeks 7–8)
**Goal:** Submission-ready.
- All: bug bash, security checks (log masking, UI escaping), README with one-command run, architecture diagram.
- All: final report (extend current progress report with design, results, limitations, future work), slides, dry-run demo twice.
- **Exit:** tagged release `v1.0`, final report + slides + demo video.

### Suggested Demo Flow (5 min)
1. Normal browsing through the WAF → dashboard shows green traffic.
2. Run attack simulator (SQLi, XSS, obfuscated variants) → blocked, red spikes.
3. Click one alert → score, matched tokens highlighted, explanation.
4. Toggle Monitor ↔ Block mode, adjust threshold.
5. Show evaluation page: ML vs ModSecurity baseline, latency overhead.
