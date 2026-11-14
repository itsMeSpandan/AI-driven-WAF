# AI-Driven Web Application Firewall (WAF) & Analytics Dashboard

## 0. End Product in Short

A **reverse-proxy WAF** that sits in front of a web application, inspects every HTTP request with a **lightweight ML detector** (SQLi, XSS, plus anomaly/bot-style traffic), blocks or flags malicious requests, and explains **why** each request was flagged. Every decision is logged and shown on a **real-time analytics dashboard** (traffic vs threats over time, attack-type breakdown, top-attacked endpoints, alert feed, per-request explanation). It ships with a vulnerable demo app and an attack-simulation script, so the whole thing can be demonstrated live: attack → blocked → appears on dashboard → explanation shown.

---

# PRD (Product Requirements Document)

## 1.1 Problem Statement
Rule-based WAFs (ModSecurity + OWASP CRS) are brittle against novel or obfuscated payloads and over-block legitimate traffic. ML-based WAF research improves detection but is typically (a) a black box, (b) weak against adversarial/evasive payloads, (c) heavy on inference cost, (d) evaluated on narrow datasets, and (e) studied separately from the analytics/visibility layer, which lives inside expensive closed SIEM suites.

## 1.2 Vision
One open, integrated, small-team-friendly system that **detects, explains and visualises** web attacks in real time.

## 1.3 Goals (mapped to gaps in the report)

| # | Gap from literature | Product goal |
|---|---|---|
| G1 | Fragmented tooling | Single integrated pipeline: detect → log → visualise |
| G2 | False positives / negatives | Learned, traffic-aware decision boundary; measured FPR lower than rule-only baseline |
| G3 | Black-box models | Per-request explanation (top contributing tokens/features + matched rule) |
| G4 | Computational overhead | Keep added latency small (target p95 < 25 ms per request) using classical ML, not heavy generative inference at runtime |
| G5 | Weak adversarial robustness | Train with obfuscation/evasion-augmented payloads; report accuracy on an evasion test set |
| G6 | Dataset scarcity/bias | Combine multiple public datasets + cross-dataset testing |
| G7 | Enterprise-only dashboards | Accessible dashboard scoped to a single app/team |

## 1.4 Non-Goals
- Not a production-grade, internet-scale WAF; no TLS termination, no clustering/HA.
- No runtime generative-AI inference in the request path (generative ideas used offline for data augmentation only).
- No deep-packet / L3-L4 DDoS mitigation (only request-rate anomaly flagging at L7).
- No automatic rule writing into ModSecurity.

## 1.5 Target Users
- **Developer / small team owner** — wants protection for their app without enterprise tooling.
- **Security analyst (student demo role)** — wants to see attack trends and justify why a request was blocked.
- **Evaluator / professor** — wants measurable results versus a baseline.

## 1.6 User Stories
1. As a developer, I place the WAF in front of my app by changing one upstream URL.
2. As a developer, I can run the WAF in **Monitor** mode (log only) or **Block** mode.
3. As an analyst, I see live traffic and threat counts for the last 5 min / 1 h / 24 h.
4. As an analyst, I click a blocked request and see its score, attack type and the tokens that triggered it.
5. As an analyst, I mark a request as false positive so it is saved for retraining.
6. As an evaluator, I run one command that reproduces precision/recall/F1/FPR/latency against the baseline.

## 1.7 Feature List (MoSCoW)

**Must have**
- Reverse proxy that forwards clean requests and blocks malicious ones (HTTP 403 page).
- ML detector for SQLi and XSS (binary + attack-type label).
- Request logging (timestamp, IP, method, path, params summary, score, verdict, attack type).
- Dashboard: live traffic vs threats chart, attack-type breakdown, top attacked endpoints, recent alerts table.
- Explainability for each flagged request.
- Evaluation script with baseline comparison.

**Should have**
- Block / Monitor mode and adjustable threshold from the dashboard.
- Light rule layer (small regex/denylist set) as a fast first pass (hybrid).
- Simple per-IP rate anomaly flag (bot-like traffic).
- False-positive feedback button.
- Demo attack simulator + vulnerable demo app.

**Could have**
- Retrain-from-feedback command.
- Path traversal / command injection classes.
- CSV/JSON export of logs; email/Telegram alert on high-severity bursts.
- GeoIP map of attack sources.

**Won't have (this version)**
- Multi-tenant auth, billing, distributed deployment.

## 1.8 Success Metrics

| Metric | Target |
|---|---|
| Detection F1 (SQLi + XSS, held-out test) | ≥ 0.95 |
| Recall on evasion/obfuscated set | ≥ 0.85 (and better than non-augmented model) |
| False positive rate on benign traffic | Lower than ModSecurity+CRS baseline at default paranoia level |
| Added latency per request | p95 < 25 ms (document actual numbers) |
| Dashboard refresh lag | < 3 s from request to chart |
| Demo | Full attack → block → dashboard → explanation flow works live |

> Targets are goals, not promises; report the measured values honestly even if they miss.

## 1.9 Constraints & Assumptions
- Student/academic scope: free tools only, runs on a laptop (Docker Compose).
- Public datasets only; no real production traffic.
- Time-boxed to the course timeline.

## 1.10 Risks (product-level)
- Dataset bias → inflated accuracy. *Mitigation:* cross-dataset evaluation (train on A, test on B).
- Overfitting to payload strings. *Mitigation:* character n-gram features + augmentation + held-out evasion set.
- Scope creep. *Mitigation:* Must-haves first, freeze scope at Stage 4.
