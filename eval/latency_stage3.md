# Stage 3 Latency Benchmark Report: Robust Pipeline & Explainer

> **Benchmark Date**: 2026-11-15
> **Hardware**: Host Machine (Local Single-Threaded Runtime)
> **Iterations**: 1,000 requests per configuration
> **Active Model**: `LogisticRegression_Augmented` (`Stage3_Robust_20261114_204029`)
> **Decision Threshold**: `0.940`

---

## 1. Summary of Results (N=1000)

| Configuration | Mean (ms) | p50 (ms) | p90 (ms) | p95 (ms) | p99 (ms) | Max (ms) | TRD Budget Status |
|---|---|---|---|---|---|---|---|
| **Bypass Baseline (WAF Off)** | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.001 | Baseline reference |
| **Rule-Only Inspection** | 0.043 | 0.048 | 0.057 | 0.058 | 0.064 | 0.092 | Sub-millisecond |
| **Robust ML Detector Alone** | 1.285 | 1.274 | 1.365 | 1.406 | 1.705 | 2.701 | **PASS** (≤ 10.0 ms budget) |
| **Stage 3 Full Pipeline (+Explainer)** | 1.811 | 1.890 | 2.227 | 2.403 | 3.017 | 3.719 | **PASS** (≤ 25.0 ms budget) |
| **Explainer Attribution Isolated** | 0.591 | 0.553 | 0.701 | 0.754 | 0.938 | 1.611 | Only runs on threats |

---

## 2. Budget Verification (TRD G4 & PRD 1.8)

- **ML Inference Budget (TRD G4)**: Target p95 $\le 10.0$ ms &rarr; **Observed 1.41 ms** (**COMPLIANT**, 8.59 ms safety margin).
- **Total WAF Overhead Budget (PRD G4)**: Target p95 $\le 25.0$ ms &rarr; **Observed 2.40 ms** (**COMPLIANT**, 22.60 ms safety margin).
- **Explainer Overhead**: Isolated token attribution and offset mapping requires **~0.75 ms p95** and is entirely bypassed on clean allowed requests, ensuring zero added latency for legitimate production traffic.

---

## 3. Comparison with Stage 2 Baseline

| Metric | Stage 2 Plain Baseline | Stage 3 Robust + Explainer | Delta |
|---|---|---|---|
| ML Detector p50 | 3.04 ms | 1.27 ms | +-1.77 ms |
| ML Detector p95 | 5.11 ms | 1.41 ms | +-3.70 ms |
| Full Pipeline p95 | 6.38 ms | 2.40 ms | +-3.98 ms |
