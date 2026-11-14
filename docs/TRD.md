# AI-Driven Web Application Firewall (WAF) & Analytics Dashboard

# TRD (Technical Requirements Document)

## 2.1 High-Level Architecture

```
 Client / Attacker
        │
        ▼
┌──────────────────────────── WAF Gateway (FastAPI + httpx) ───────────────────────────┐
│ 1. Request parser/normaliser (URL-decode, lower-case, strip comments, merge params)  │
│ 2. Fast rule layer (small denylist)  ──hit──► BLOCK / FLAG                           │
│ 3. ML detector (vectoriser + classifier) ──score≥threshold──► BLOCK / FLAG           │
│ 4. Explainer (top features for flagged requests)                                     │
│ 5. Forward clean traffic to upstream app                                             │
└───────────────┬───────────────────────────────────────────────┬──────────────────────┘
                │ async log write                                │ forward
                ▼                                                ▼
        ┌───────────────┐                              ┌──────────────────┐
        │ Log DB        │◄──── REST + SSE/WebSocket ───│ Protected App    │
        │ (SQLite/PG)   │            ▲                 │ (DVWA/Juice Shop)│
        └───────────────┘            │                 └──────────────────┘
                                     │
                          ┌──────────┴───────────┐
                          │ Analytics Dashboard  │
                          │ (Next.js + Recharts) │
                          └──────────────────────┘

 Offline: data prep → augmentation → training → evaluation → model.joblib (loaded by gateway)
```

## 2.2 Components

| Component | Responsibility | Tech |
|---|---|---|
| WAF Gateway | Reverse proxy, inspection pipeline, block/monitor logic | Python 3.11, FastAPI, httpx (async), uvicorn |
| Detector | Feature extraction + classification | scikit-learn (TF-IDF char n-grams + Logistic Regression / Random Forest / Decision Tree; pick by benchmark), joblib |
| Explainer | Why was it flagged | Linear-model coefficients × TF-IDF values (fast) and/or SHAP/LIME for offline analysis; matched rule ID |
| Rule layer | Cheap first-pass signatures | ~20–40 hand-picked regexes (OWASP-inspired) |
| Augmenter (offline) | Evasion-style payload variants | Python mutation functions (case flip, inline comments `/**/`, URL/double encoding, whitespace/Unicode tricks, concatenation); optional LLM-generated variants offline |
| Log store | Persist verdicts | SQLite for dev (PostgreSQL optional) via SQLAlchemy |
| Dashboard API | Aggregations + live stream | FastAPI routes, Server-Sent Events |
| Dashboard UI | Visualisation | Next.js (App Router), Tailwind, Recharts |
| Demo target | Vulnerable app | DVWA or OWASP Juice Shop in Docker |
| Attack simulator | Reproducible demo/test traffic | Python script + payload lists (+ optionally sqlmap against demo app) |
| Baseline | Comparison | ModSecurity + OWASP CRS (`owasp/modsecurity-crs` Docker image) |

## 2.3 Data & Model Plan

**Datasets (public; verify licences/availability when downloading)**
- HTTP request corpus with normal/anomalous traffic: CSIC 2010 HTTP dataset.
- SQLi payload/query datasets and XSS payload datasets from Kaggle/GitHub (e.g. SecLists, PortSwigger cheat-sheet payloads, public SQLi/XSS CSVs).
- Benign traffic: CSIC normal requests + synthetic benign requests generated from the demo app's normal usage.
- Held-out sets: (a) random test split, (b) **cross-dataset** set, (c) **evasion set** built by augmentation functions *not used in training* (use different mutation families for test).

**Pipeline**
1. Normalise request → single text string (method + path + decoded params + selected headers).
2. Deduplicate; split train/val/test **before** augmentation to avoid leakage.
3. Feature extraction: TF-IDF on character n-grams (e.g. 2–5) + a few handcrafted features (length, special-char ratio, keyword counts, entropy).
4. Train and compare: Logistic Regression, Linear SVM, Decision Tree, Random Forest (literature: Decision Tree strong on F1 — verify on our data).
5. Train second variant with augmented data; compare robustness.
6. Calibrate threshold for target FPR; save `model.joblib` + `vectorizer.joblib` + `metadata.json` (version, metrics, threshold).

**Attack-type label:** multi-class (benign / sqli / xss / other-anomaly) or two-stage (binary → type via rule/class).

## 2.4 Explainability Design
- For linear models: top-k n-grams with positive contribution to the malicious score, returned as `[ {token, weight} ]`.
- Always include `matched_rule` if the rule layer fired.
- UI renders the original request with highlighted offending substrings.
- Offline: SHAP/LIME report for analysis and the final report (not in request path).

## 2.5 Performance Requirements
- Gateway fully async; model loaded once at startup; vectoriser + predict on a single request in a few ms.
- Logging is non-blocking (queue/background task) so it never delays the response.
- Request body inspection capped (e.g. first 8–16 KB) to bound cost.
- Benchmark with `wrk`/`locust`/`hey`: report baseline (direct app), with rule-only, with ML.

## 2.6 API Specification (draft)

**Gateway (data plane):** all paths proxied to upstream; blocked → `403` with request ID.

**Dashboard API (control/analytics plane):**

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/stats/summary?range=1h` | Totals: requests, blocked, flagged, block rate |
| GET | `/api/stats/timeseries?range=1h&bucket=1m` | Traffic vs threats time series |
| GET | `/api/stats/attack-types` | Breakdown by attack type |
| GET | `/api/stats/top-endpoints` | Most attacked paths |
| GET | `/api/stats/top-ips` | Top source IPs |
| GET | `/api/events?limit=&type=&verdict=` | Paginated log of requests |
| GET | `/api/events/{id}` | Single event + explanation |
| GET | `/api/stream` | SSE live feed of new events |
| POST | `/api/events/{id}/feedback` | Mark false positive / confirmed attack |
| GET / PUT | `/api/config` | Mode (monitor/block), threshold, rate-limit settings |

## 2.7 Database Schema (draft)

```
events(
  id UUID PK, ts TIMESTAMP, client_ip TEXT, method TEXT, path TEXT,
  query_summary TEXT, body_summary TEXT, user_agent TEXT,
  rule_hit TEXT NULL, ml_score REAL, verdict TEXT,        -- allow | flag | block
  attack_type TEXT, latency_ms REAL, explanation JSON,
  feedback TEXT NULL                                       -- fp | tp | NULL
)
config(key TEXT PK, value TEXT)
model_versions(id, created_at, metrics JSON, threshold REAL, active BOOL)
```
Indexes on `ts`, `verdict`, `attack_type`, `path`.

## 2.8 Dashboard Specification

| Panel | Content |
|---|---|
| KPI cards | Total requests, blocked, flagged, block rate, avg latency |
| Traffic vs Threats | Time-series line/area chart (live) |
| Attack-type breakdown | Donut/bar chart |
| Top attacked endpoints | Ranked table/bar chart |
| Live alert feed | Streaming table with severity badge |
| Request detail drawer | Raw request, score, matched rule, highlighted tokens, feedback buttons |
| Settings | Mode toggle, threshold slider |
| Model/Eval page | Metrics of active model, baseline comparison table |

## 2.9 Security & Privacy Requirements
- Dashboard behind simple auth (single admin login/JWT or basic auth).
- Mask sensitive values (passwords, tokens, cookies) before logging.
- Gateway fails **open or closed** by config (default: closed for demo, document the choice).
- Escape all logged content in the UI (avoid XSS on the dashboard itself — attack payloads are stored there!).
- No real user data; all traffic synthetic.

## 2.10 Deployment
- `docker-compose.yml`: `waf-gateway`, `dashboard-api` (can be same service), `dashboard-ui`, `db`, `demo-app`, optional `modsecurity-baseline`.
- Single `make demo` / script to bring everything up and run the attack simulator.

## 2.11 Suggested Repo Structure

```
ai-waf/
├─ gateway/            # FastAPI proxy, rule layer, detector loader, explainer
├─ ml/
│  ├─ data/            # raw + processed (gitignored large files)
│  ├─ augment/         # mutation functions
│  ├─ train.py  evaluate.py  explain.py
│  └─ models/          # model.joblib, metadata.json
├─ dashboard/
│  ├─ api/             # stats + stream routes
│  └─ ui/              # Next.js app
├─ demo/               # vulnerable app compose, attack simulator, payloads
├─ eval/               # baseline (ModSecurity) config, latency benchmarks, results
├─ docs/               # report, PRD/TRD, diagrams
└─ docker-compose.yml
```

## 2.12 Evaluation Plan
1. **Detection quality:** precision, recall, F1, ROC-AUC, confusion matrix on test split.
2. **Generalisation:** train on dataset A, test on dataset B.
3. **Robustness:** recall on evasion set — plain model vs augmented model.
4. **False positives:** run benign traffic through ModSecurity+CRS and our WAF; compare FPR.
5. **Latency/throughput:** requests/sec and p50/p95 with WAF off, rule-only, rule+ML.
6. **Explainability sanity check:** manual review of top tokens on ~30 flagged samples.
7. **End-to-end demo script** with expected outcomes.

## 2.13 Technical Risks

| Risk | Mitigation |
|---|---|
| Overfit/leakage inflating scores | Split before augmentation, cross-dataset test |
| Latency too high | Linear models, capped body size, async I/O, hybrid fast-path |
| Dataset licence/availability | Keep 2–3 alternatives; document sources |
| Dashboard lag under load | Aggregate in SQL, batch SSE pushes |
| Baseline ModSecurity setup time | Use prebuilt CRS Docker image; timebox to 1 day |
| Team integration delays | Freeze API contract (Section 2.6) in Stage 1 |
