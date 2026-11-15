# AI-Driven Web Application Firewall (WAF) & Real-Time Analytics Dashboard

An integrated, defensive AI-powered Web Application Firewall (WAF) reverse-proxy paired with a live security-operations analytics dashboard. Built for course mini-project evaluation.

---

## Architecture Overview

```
                      Client / Attacker
                             │
                             ▼
  ┌────────────────────────────────────────────────────────────┐
  │                   WAF Gateway (:8080)                      │
  │  FastAPI + httpx Async Reverse-Proxy                       │
  │  1. Request normalisation (iterative decode, NFKC, comments)│
  │  2. Rule Layer (fast OWASP-style regex signatures)         │
  │  3. ML Detector (TF-IDF char n-grams + Linear/Tree model)   │
  │  4. Verdict: Allow (forward) / Flag / Block (HTTP 403)     │
  │  5. Explainer: contributing tokens & rule hits             │
  │  6. Non-blocking asynchronous event logging                │
  └───────────────┬────────────────────────────┬───────────────┘
                  │ async log write             │ forward clean
                  ▼                             ▼
  ┌───────────────────────────────┐     ┌───────────────────────┐
  │        Database Store         │     │ Protected Application │
  │    SQLite / PostgreSQL        │     │  OWASP Juice Shop     │
  └───────────────┬───────────────┘     │  (internal :3000)     │
                  │ REST / SSE          └───────────────────────┘
                  ▼
  ┌───────────────────────────────┐
  │    Dashboard API (:8000)      │
  │  FastAPI / Stats / SSE Stream │
  └───────────────┬───────────────┘
                  │ REST / SSE
                  ▼
  ┌───────────────────────────────┐
  │     Dashboard UI (:3000)      │
  │  Next.js 14, TailwindCSS,     │
  │  Recharts, Dark SecOps Theme  │
  └───────────────────────────────┘
```

---

## Key Features

- **Layer 7 Reverse-Proxy**: Asynchronous pass-through proxy with minimal latency overhead.
- **Deep Normalisation**: Canonical request representation handling multi-layer URL encoding, HTML entities, Unicode NFKC, comment stripping, and duplicate parameters.
- **Hybrid Inspection Pipeline**: Fast rule-based denylist check paired with ML threat scoring.
- **Transparent Explainability**: Extracts top contributing character n-grams and matched rule IDs for flagged requests.
- **Real-Time SecOps Dashboard**: Real-time traffic vs threats time-series, attack-type distribution, top targeted endpoints, live SSE alert stream, and request inspection drawer with XSS-safe escaping.
- **Demo & Evaluation Ready**: Ships with containerized OWASP Juice Shop and a safe attack simulator.

---

## Repository Structure

```
ai-waf/
├── gateway/             # FastAPI reverse proxy, normalisation, detection pipeline
├── dashboard/
│   ├── api/             # Analytics REST API, SSE streaming, SQLite/PG storage
│   └── ui/              # Next.js 14 App Router dashboard with Tailwind & Recharts
├── ml/
│   ├── data/            # Dataset acquisition scripts and schemas (raw files gitignored)
│   ├── augment/         # Evasion payload mutation utilities
│   ├── models/          # Exported vectorizer & model joblibs + metadata
│   └── notebooks/       # Exploratory Data Analysis & evaluation notebooks
├── demo/
│   ├── payloads/        # Textbook benign and attack payload samples
│   └── attack_simulator.py # Controlled local traffic generator
├── eval/                # ModSecurity baseline configs and benchmark results
├── docs/                # PRD, TRD, STAGES, API contracts, and PROGRESS tracker
└── docker-compose.yml   # Multi-service stack definition
```

---

## Quickstart

### 1. Prerequisites
- Docker and Docker Compose v2+
- Python 3.11+
- Node.js 18+ & npm

### 2. Environment Setup
```bash
cp .env.example .env
```

### 3. Start Stack with Docker Compose
```bash
make up
# or
docker compose up -d --build
```

The services will be available at:
- **WAF Entrypoint**: `http://localhost:8080` (routes to protected application)
- **Analytics Dashboard**: `http://localhost:3000`
- **Dashboard API & Docs**: `http://localhost:8000/docs`

### 4. Data Preparation & Model Training
To download raw training corpora (SecLists and CSIC 2010), canonicalize, and train the ML detector:
```bash
make data   # Download raw corpora and prepare stratified train/val/test splits
make train  # Train 4 candidate models, calibrate threshold, export model.joblib
```

### 5. Benchmark Latency Overhead
To benchmark request latency across WAF Off, Rule-Only, Full Pipeline, and Explainer Attribution:
```bash
python eval/benchmark_latency_stage3.py
# Report saved to eval/latency_stage3.md
```

### 6. Evaluate Robustness & Cross-Source Transfer
```bash
python ml/cross_eval.py               # Generates ml/reports/cross_source.md
python eval/generate_explainer_review.py # Generates eval/explainer_review.md
```

### 7. Seed Demo Telemetry
```bash
make seed
# or
python dashboard/api/seed_demo_data.py
```

### 8. Run the Attack Simulator (Including Evasions & Burst Mode)
```bash
make demo
# or test zero-day evasion mutations:
python demo/attack_simulator.py --target http://localhost:8080 --count 30 --types sqli,xss,evasion_a,evasion_b,benign
# or simulate rapid scanner bursts to trigger rate limiting:
python demo/attack_simulator.py --target http://localhost:8080 --burst --count 50
```

### 9. Safe Feedback Retraining & Model Promotion (Stage 4)
```bash
# Ingest analyst feedback, train candidate model, evaluate 4 safety gates:
python ml/retrain_feedback.py
# Promote candidate model if all gates pass (creates atomic backup):
python ml/retrain_feedback.py --promote
# Roll back to previous active model if needed:
python ml/retrain_feedback.py --rollback
```

### 10. Run Test Suites
```bash
make test
# runs full test suite: pytest -v gateway/tests dashboard/api/tests ml/tests eval/tests
```

### 11. Run Stage 5 Evaluation & Benchmarking vs ModSecurity + CRS
To execute the complete head-to-head evaluation pipeline:
```bash
make eval        # Executes dual-engine replay, latency benchmarks, SHAP study, and plots
# or for a quick test:
make eval-quick  # Runs rapid smoke evaluation (< 60s)
```
Key Stage 5 evaluation artifacts:
- **Head-to-Head Comparison Report**: [`eval/results.md`](eval/results.md)
- **Model Card**: [`docs/MODEL_CARD.md`](docs/MODEL_CARD.md)
- **5-Minute Demo Script**: [`docs/DEMO.md`](docs/DEMO.md)
- **Benchmark Visual Figures**: [`eval/figures/`](eval/figures/) (`roc_curves.png`, `confusion_matrices.png`, `latency_concurrency.png`)
- **Interpretability Study**: [`eval/results/interpretability.md`](eval/results/interpretability.md)

---

## Benchmark Headline Results (Stage 5)

| Metric | AI-WAF Hybrid (Rules + ML) | ModSecurity CRS v4 (PL1) | Notes / Advantage |
|:---|:---:|:---:|:---|
| **In-Distribution Attack Recall** | **97.94%** [96.9–98.7%] | 27.48% [24.8–30.3%] | AI-WAF sub-tokens catch tautologies |
| **Zero-Day Evasion Recall (Family B)** | **90.32%** [88.1–92.1%] | 24.15% [21.4–27.1%] | +66.2% lift on unseen obfuscated attacks |
| **Neutral Benchmark Recall** | **83.60%** [80.1–86.6%] | 32.40% [28.4–36.6%] | Independent cross-attack benchmark |
| **False Positive Rate (Benign)** | **0.00%** [0.00–0.12%] | 0.00% [0.00–0.12%] | Zero false alarms across 4,507 clean requests |
| **Single-Request Latency (p95)** | **2.55 ms** | 4.80 ms | Sub-millisecond linear token explainer |
| **Composite Serial Recall** | **98.04%** | 98.04% | Running both in series eliminates blind spots |

---

## Operating Modes

The WAF Gateway supports two runtime modes configured via `.env` (`WAF_MODE`), runtime DB settings, or the Dashboard UI:
- **`block`** (Enforcement Mode): Malicious requests violating rules or exceeding the ML threshold ($0.940$) are immediately rejected with an HTTP 403 Forbidden page and tracked with an incident Request ID.
- **`monitor`** (Telemetry / Dry-Run Mode): All requests are forwarded to the upstream application (HTTP 200), but threats are flagged with `x-waf-verdict: flag` and logged to the analytics database for SecOps review.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
