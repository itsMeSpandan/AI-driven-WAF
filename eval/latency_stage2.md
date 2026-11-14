# Stage 2 Latency Benchmark Report

**Date**: 2026-11-15  
**Hardware / OS**: Windows / Python 3.15.2 (Single-thread synchronous request timings)  
**Sample Size**: 1,000 individually timed requests per mode  
**Target Latency Budget (TRD G4 & STAGES.md)**:
- ML inference alone: $p95 \le 10.0$ ms
- Total WAF pipeline overhead: $p95 \le 25.0$ ms

---

## 1. Summary Comparison

| Configuration | Mean (ms) | Median / p50 (ms) | p90 (ms) | p95 (ms) | p99 (ms) | Max (ms) | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **WAF Off / Bypass** | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.001 | Baseline |
| **Rule-Only** (Normalisation + 29 Regexes) | 0.044 | 0.049 | 0.061 | 0.062 | 0.079 | 0.131 | PASS |
| **ML Inference Alone** (TF-IDF + Lexical + LogReg) | 1.475 | 1.392 | 1.838 | 2.002 | 2.371 | 2.877 | PASS (Budget: $\le$ 10 ms) |
| **Full Pipeline: Rule + ML** (End-to-End WAF) | 1.457 | 1.415 | 1.656 | 1.794 | 2.039 | 3.165 | PASS (Budget: $\le$ 25 ms) |

---

## 2. Key Observations

1. **ML Inference Latency**:
   - The ML step alone achieves a median latency of **1.39 ms** and a 95th percentile of **2.00 ms**.
   - This comfortably complies with the **$\le 10$ ms** budget requirement in TRD G4 and STAGES.md Task 3.
2. **Rule Layer Overhead**:
   - The bounded regex rule evaluation combined with multi-pass normalisation adds only **~0.05 ms** median latency.
   - ReDoS immunity guarantees absence of long-tail catastrophic stalls (p99 = 0.08 ms).
3. **Full Pipeline Budget Compliance**:
   - Total end-to-end WAF inspection overhead (Normalisation + Rules + ML + Decision) achieves a p95 latency of **1.79 ms**, well below the **$\le 25.0$ ms** project budget.
4. **Asynchronous Non-Blocking Execution**:
   - In the live FastAPI gateway, `ml_score` runs via `asyncio.to_thread` and logging is dispatched via an in-memory `asyncio.Queue` background worker, preventing inspection and DB persistence from blocking concurrent client event loops.
