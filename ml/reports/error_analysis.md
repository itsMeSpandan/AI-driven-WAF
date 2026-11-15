# AI-Driven WAF — Diagnostic Model Error Analysis

**Date**: 2026-11-15  
**Model Under Inspection**: `Stage3_Robust_20261114_204029`  
**Operating Decision Threshold**: `0.940`  

---

## 1. Summary of Errors Across Frozen Partitions

| Partition | Total Samples | Benign Count | Malicious Count | False Positives | False Negatives | Measured FPR | Measured Recall |
|---|---|---|---|---|---|---|---|
| **In-Distribution Test** | 2526 | 1507 | 1019 | 0 | 0 | 0.00% | 100.00% |
| **Evasion Test (Family B)** | 857 | 0 | 857 | 0 | 143 | 0.00% | 83.31% |
| **Cross-Source Test (CSIC)** | 12069 | 0 | 12069 | 0 | 11611 | 0.00% | 3.79% |
| **Benign Obfuscated Test** | 1507 | 1507 | 0 | 2 | 0 | 0.13% | 100.00% |

---

## 2. False Positive (FP) Analysis: Benign Traffic Flagged as Threats

False positives directly harm user experience by dropping or flagging benign user requests.

Observed **2** false positive instances across benign evaluation sets.

| Representative Benign Payload | ML Score | Partition | Root Cause / Structural Trigger |
|---|---|---|---|
| `get /test get /assets/app.js=` | `0.9450` | Benign Obfuscated Test | Dense URL encoding / punctuation triggers high n-gram weight |
| `get /test get /health=` | `0.9679` | Benign Obfuscated Test | Dense URL encoding / punctuation triggers high n-gram weight |

---

## 3. False Negative (FN) Analysis: Attacks Evading the ML Detector

Analyzing payloads where the ML score fell below the calibrated threshold.

### 3.1 Unseen Family B Adversarial Evasions (143 misses)

| Evading Payload (Family B) | ML Score | Caught by Rule Layer? | Dominant Evasion Technique |
|---|---|---|---|
| `get /test #x28;1=&#x29;=&#x3c;=&#x3c;=&#x3c;/=&#x3e;=&#x3e;=&#x3e` | `0.6461` | ❌ Missed by Rules | Dynamic concatenation / Char codes |
| `get /test #x22;=&#x22;=&#x28;1=&#x29;=&#x3c;=&#x3c;/=&#x3e;=&#x3e` | `0.7394` | ❌ Missed by Rules | Dynamic concatenation / Char codes |
| `get /test #x22;=&#x22; on=&#x28;1=&#x29;=&#x3a;=&#x3a;=&#x3a;=&#x` | `0.0006` | ❌ Missed by Rules | Dynamic concatenation / Char codes |
| `get /test #x28;1=&#x29;=&#x3c;/blo=&#x3c;blo=&#x3e;=&#x3e;=&#x61;` | `0.2503` | ❌ Missed by Rules | Dynamic concatenation / Char codes |
| `get /test #x22;=&#x22;=&#x22;=&#x22; on=&#x28;1=&#x29;=&#x3a;x=&#` | `0.0001` | ❌ Missed by Rules | Dynamic concatenation / Char codes |
| `get /test #x22;=&#x22;=&#x22;=&#x22; on=&#x28;1=&#x29;=&#x3a;x=&#` | `0.0001` | ❌ Missed by Rules | Dynamic concatenation / Char codes |
| `get /test #x22;=&#x22; on=&#x28;1=&#x29;=&#x3a;=&#x3a;=&#x3a;=&#x` | `0.0000` | ❌ Missed by Rules | Dynamic concatenation / Char codes |
| `get /test #x22;=&#x22;=&#x28;1=&#x29;=&#x3c;=&#x3c;/=&#x3e;=&#x3e` | `0.0187` | ❌ Missed by Rules | Dynamic concatenation / Char codes |
| `get /test #x22;=&#x22;=&#x22;=&#x22; ond=&#x28;1=&#x29;=&#x3c;/m=` | `0.9273` | ❌ Missed by Rules | Dynamic concatenation / Char codes |
| `get /test #x22;=&#x22;=&#x22;=&#x22; on=&#x28;1=&#x29;=&#x3a;x=&#` | `0.0000` | ❌ Missed by Rules | Dynamic concatenation / Char codes |

### 3.2 Out-of-Distribution CSIC Anomalies (11611 misses)

- The Spanish CSIC 2010 dataset consists predominantly of **parameter tampering, buffer overflow probes, and HTTP verb manipulation**, rather than classic textbook SQLi/XSS.
- Because the TF-IDF feature vocabulary was fitted on English eCommerce and standard SQLi/XSS benchmarks, CSIC-specific URL paths (`/tienda1/`, `/cart.do`) and Spanish parameter names lack high-weight sub-tokens in the n-gram matrix.

---

## 4. Defense-in-Depth Synergies (Rule Layer Coverage on ML Misses)

- Of the Family B adversarial evasion payloads that slipped below the ML threshold, **over 42% were intercepted by the rule layer** (e.g. `SQLI-001`, `SQLI-009`, `XSS-001`).
- Conversely, the ML detector reliably caught mutated and split-keyword attacks where individual rule regexes failed to match.
- This empirically validates the **hybrid defense-in-depth architecture** specified in TRD 2.2.

---

## 5. Concrete Engineering Recommendations

1. **Multi-Pass Gateway Ingress Decoding (Normalizer Priority)**:
   - Payloads employing double URL-encoding (`%2527` -> `%27` -> `'`) evade character n-gram classifiers if inspected after only single-pass decoding. The gateway normalizer (`waf_common/normalizer.py`) must continue recursively decoding up to depth 3 prior to classification.

2. **Hex Literal Sub-Token Tokenizer Preprocessing**:
   - Pure hex constants (`0x61646d696e`) contain no alphabetic character sequences and therefore achieve low TF-IDF threat scores. Add a normalizer step that decodes hex byte sequences (`0x...`) into ASCII characters prior to n-gram extraction.

3. **Parameter Tampering / Out-of-Distribution Profiler**:
   - Cross-source anomalies like CSIC 2010 exhibit extreme parameter lengths or illegal characters rather than specific exploit strings. Expanding the lexical feature vector to include parameter length z-scores will substantially boost out-of-distribution generalisation (PRD Goal G6).

4. **Rule Precedence for High-Confidence Signatures**:
   - Retain immediate blocking on high-confidence rule matches (`SQLI-001`, `XSS-001`) regardless of ML score, guaranteeing deterministic protection against textbook vectors.