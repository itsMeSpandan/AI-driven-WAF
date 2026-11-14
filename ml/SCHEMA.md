# Machine Learning Dataset Schema & Engineering Rules

This document specifies the standard representation for datasets across training, evaluation, and evasion testing in the AI WAF ML workspace.

---

## 1. Dataset Columns (Standard CSV / Parquet)

Every prepared dataset in `ml/data/processed/` must contain the following columns:

| Column | Data Type | Permitted Values | Description |
|---|---|---|---|
| `text` | `string` (non-null) | Normalised HTTP text | Canonical representation generated via `normalise_request()` |
| `label` | `integer` (0 or 1) | `0` = Benign, `1` = Malicious | Binary ground truth label for threat classification |
| `attack_type` | `string` | `benign`, `sqli`, `xss`, `bot_anomaly` | Specific payload taxonomy class |
| `source` | `string` | `csic2010`, `seclists`, `portswigger`, `sample` | Origin dataset or acquisition generator |
| `split` | `string` | `train`, `val`, `test`, `evasion` | Designated partition |

---

## 2. The Golden Rule: Split Before Augmentation

> [!CRITICAL]
> **NEVER apply augmentation or mutation functions before splitting the dataset.**

### Why?
Applying synthetic mutations (URL encoding, comment-injection, case flipping) to a combined dataset before splitting causes **data leakage**:
- The model memorizes structural tokens from the parent payload that appear in both the training set and the test set.
- This creates artificially inflated test accuracy (>99%) that catastrophically collapses when confronted with novel real-world attacks.

### Mandatory Workflow
```
Raw Corpus ──► Deduplication ──► Canonical Normalisation
                                        │
                         ┌──────────────┴──────────────┐
                         ▼                             ▼
                    Train Split (70%)             Test Split (30%)
                         │                             │
                         ▼                             ▼
                 Apply Augmentation           HELD OUT (No Augmentation)
               (Case, comments, etc.)         or test on unseen evasion families
```
