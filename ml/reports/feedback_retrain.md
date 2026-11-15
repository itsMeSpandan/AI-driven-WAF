# AI-Driven WAF — Feedback Retraining & Model Safety Gate Report

**Date**: 2026-11-15  
**Active Baseline Model**: `Stage3_Robust_20261114_204029` (Threshold: `0.940`)  
**Candidate Model**: `Candidate_Feedback_20261115_044617` (Threshold: `0.940`)  
**Overall Gate Verdict**: **APPROVED FOR PROMOTION (PASS)**  

---

## 1. Analyst Feedback Summary & Poisoning Defense

- **Total Deduplicated Samples Merged**: 1
  - **Benign Corrections (FP)**: 1
  - **Malicious Confirmations (TP)**: 0
- **Adversarial Rule Conflicts Intercepted**: 0

---

## 2. Automated Safety Promotion Gates Evaluation

| Gate # | Safety Criterion | Target Bound | Candidate Measured | Status |
|---|---|---|---|---|
| **Gate 1** | Benign False Positive Rate on `test.csv` | $\le 2.50\%$ | **0.07%** | **PASS** |
| **Gate 2** | Evasion Recall Drop on `evasion_test.csv` | $\le 2.00\%$ drop vs active | **84.36%** (delta: +1.05%) | **PASS** |
| **Gate 3** | Cross-Source Generalisation on CSIC | $\le 2.00\%$ drop vs active | **4.24%** (delta: +0.45%) | **PASS** |
| **Gate 4** | p95 Single-Request Latency | $\le 10.00\text{ ms}$ | **2.55 ms** | **PASS** |

---

## 3. Side-by-Side Model Performance Matrix

| Partition / Benchmark | Active Model Metric | Candidate Model Metric | Delta |
|---|---|---|---|
| **Test F1 Score** | 1.0000 | 0.9990 | -0.0010 |
| **Test False Positive Rate (FPR)** | 0.00% | 0.07% | +0.07% |
| **Unseen Evasion Recall (Family B)** | 83.31% | 84.36% | +1.05% |
| **Benign Obfuscated Test FPR** | 0.13% | 0.13% | +0.00% |
| **Cross-Source CSIC Recall** | 3.79% | 4.24% | +0.45% |
| **Cross-Source CSIC F1** | 0.0731 | 0.0814 | +0.0083 |
| **Single Request Latency (p50 / p95)** | 1.88 ms / 2.63 ms | 1.84 ms / 2.55 ms | -0.09 ms |

---

## 4. Governance & Deployment Recommendation
- **Gate Evaluation**: Candidate satisfied all 4 automated promotion criteria.
- **Command to Promote**: `python ml/retrain_feedback.py --promote` (or `make promote-model`)
- **Command to Rollback**: `python ml/retrain_feedback.py --rollback` (or `make rollback-model`)

> [!NOTE]
> Frozen test sets (`test.csv`, `evasion_test.csv`, `cross_source_test.csv`, `benign_obfuscated_test.csv`) remain completely untouched and unmodified, guaranteeing unbiased out-of-sample evaluation.