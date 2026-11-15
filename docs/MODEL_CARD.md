# Model Card — Hybrid AI-WAF Machine Learning Detector

This Model Card adheres to the standard proposed by Mitchell et al. (2019) and documents the production detection model deployed within the **AI-Driven Web Application Firewall (WAF)**.

---

## 1. Model Details

- **Model Identifier**: `Stage3_Robust_20261114_204029`
- **Model Architecture**: Logistic Regression with Combined Feature Union (`TfidfVectorizer` + `LexicalFeatureExtractor`)
- **Hyperparameters**:
  - `classifier__C`: `5.0`
  - `classifier__solver`: `lbfgs`
  - `classifier__max_iter`: `1000`
  - `classifier__random_state`: `42`
  - `features__tfidf__analyzer`: `char`
  - `features__tfidf__ngram_range`: `(3, 5)`
  - `features__tfidf__max_features`: `20,000`
- **Decision Threshold ($\tau$)**: `0.940` (Calibrated on validation split subject to $\text{FPR} \le 2.5\%$ and $p95 \le 10.0\text{ ms}$)
- **Release Date**: November 2026
- **License**: MIT
- **Developers**: 3-Person Mini-Project Student Engineering Team

---

## 2. Intended Use & Target Tasks

### Primary Intended Uses
- Real-time HTTP request scoring and anomaly detection at the reverse proxy gateway (`FastAPI` + `httpx`).
- Inline defense-in-depth classification alongside a deterministic signature rule layer.
- Detection of web injection attacks including SQL Injection (SQLi), Cross-Site Scripting (XSS), Path Traversal / LFI, and adversarial mutations.
- Generation of interpretable token attribution spans for security analyst review on the Next.js analytics dashboard.

### Out-of-Scope & Misuse
- **Primary Authentication / Authorization**: The model is not an identity provider or authorization enforcer.
- **DDoS / Volumetric Scrubbing**: The ML scoring pipeline operates on individual normalized payloads; volumetric traffic floods must be scrubbed upstream via rate limiters and burst mitigators.
- **Deep Encrypted Payloads**: Payloads encapsulated within custom encrypted binaries without proxy TLS termination cannot be inspected.
- **Unsupervised / Autonomous Adaptation**: The model does not train online during live traffic; updates must follow safe shadow-mode validation (`ml/retrain.py`).

---

## 3. Training & Validation Data

### Data Sources
1. **Malicious Web Traffic**:
   - Curated SQL injection and XSS exploit vectors sourced from public security benchmarks (PayloadsAllTheThings, SecLists).
   - Adversarial Family A mutations generated via `ml/augment.py` (case alteration, inline comments `/* */`, whitespace manipulation, URL hex encoding, operator substitutions).
2. **Benign Traffic**:
   - HTTP CSIC 2010 normal traffic corpus (Spanish National Research Council).
   - Synthetic realistic eCommerce browsing and checkout traces generated against OWASP Juice Shop and DVWA endpoints.
3. **Volume**:
   - Total augmented training set: **16,824 requests**
   - Held-out validation split: **2,525 requests**
   - Zero-sample leakage: Strict hash-verified disjointness against all test evaluation corpora.

---

## 4. Quantitative Performance Summary

All metrics reported with **Wilson 95% Confidence Intervals** evaluated on frozen test corpora during Stage 5 benchmarking.

| Evaluation Corpus | Size ($N$) | Metric | Active Robust Model (`Stage3_Robust`) | Stage 2 Baseline Model | ModSecurity CRS PL1 Baseline |
|:---|:---:|:---:|:---:|:---:|:---:|
| **In-Distribution Test** | 2,526 | Recall (Attacks)<br>FPR (Benign)<br>F1-Score | **100.0%** [99.6–100.0%]<br>**0.00%** [0.00–0.25%]<br>**1.0000** | 100.0% [99.6–100.0%]<br>0.00% [0.00–0.25%]<br>1.0000 | 27.48% [24.8–30.3%]<br>0.00% [0.00–0.25%]<br>0.4311 |
| **Unseen Family B Evasions** | 857 | Recall (Attacks) | **89.85%** [87.6–91.7%] | 77.60% [74.7–80.3%] | 24.15% [21.4–27.1%] |
| **Neutral Independent Corpus** | 1,000 | Recall (Attacks)<br>FPR (Benign) | **56.80%** [52.4–61.1%]<br>**0.00%** [0.00–0.74%] | 48.20% [43.8–52.6%]<br>0.00% [0.00–0.74%] | 32.40% [28.4–36.6%]<br>0.00% [0.00–0.74%] |
| **Cross-Source CSIC 2010** | 12,069 | Recall (Attacks) | **1.18%** [1.00–1.40%]<br>*(Hybrid: 20.29%)* | 0.85% [0.70–1.04%]<br>*(Hybrid: 20.29%)* | 15.15% [14.5–15.8%] |
| **Large Benign Corpus** | 3,000 | False Positive Rate | **0.00%** [0.00–0.12%] | 0.00% [0.00–0.12%] | 0.00% [0.00–0.12%] |
| **Latency Benchmark (p95)** | 1,000 | Processing Time | **2.55 ms** | 2.48 ms | 4.80 ms |

---

## 5. Interpretability & Explainability

- **Method**: Local Linear Feature Attribution (`gateway/explainer.py`) backed by Game-Theoretic Shapley validation (`eval/shap_analysis.py`).
- **Mechanism**: Calculates non-zero TF-IDF feature contributions $w_i \cdot x_i$, maps character n-grams to precise byte/character offsets in canonical request text, and aggregates dense lexical counters.
- **Faithfulness**: Exhibits **80.0%** feature alignment with offline exact KernelSHAP while executing in **< 1.0 ms** (sub-millisecond overhead).

---

## 6. Limitations & Failure Modes

1. **Severe Out-of-Distribution Domain Shift**:
   - When exposed to radically different web application schemas with novel Spanish URL query parameters (e.g. CSIC 2010 `/tienda1/`), the ML model alone exhibits a severe recall drop (1.18%).
   - **Mitigation**: The AI-WAF hybrid architecture pairs the ML model with high-confidence regex rules (`evaluate_rules`), maintaining a 20.29% baseline safety net that out-detects ModSecurity PL1 (15.15%).
2. **Double-Nested Obfuscation (Family B)**:
   - Deeply nested character coding tricks (such as multi-stage `String.fromCharCode` with concatenation) bypass n-gram matching when token frequencies resemble arbitrary strings.
   - **Mitigation**: Normalizer URL-decodes and canonicalizes whitespace prior to vectorization; operator feedback retrains candidate models safely.
3. **Payload Length Bounds**:
   - Inspection window caps canonicalized text to 4,096 characters to prevent ReDoS or polynomial vectorization memory spikes. Extremely long file uploads must be scanned out-of-band.

---

## 7. Governance, Safety & Deployment Guidance

- **Operating Modes**:
  - `monitor`: Logs requests, computes scores and token explanations, passes traffic upstream without disruption. (Recommended during initial 48-hour onboarding).
  - `block`: Denies requests whose score exceeds $\tau = 0.940$ or hit signature rules with HTTP 403 Forbidden.
- **Fail-Open Default**: Gateway network errors or upstream timeouts default to pass-through with warning telemetry rather than causing cascading business downtime.
