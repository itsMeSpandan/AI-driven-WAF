# Machine Learning Workspace

This directory contains the data preparation, feature extraction, model training, and evaluation pipelines for the AI-Driven Web Application Firewall.

---

## Directory Structure

```
ml/
├── data/
│   ├── raw/             # Raw candidate datasets (gitignored)
│   ├── processed/       # Canonical normalized & deduplicated splits (train/val/test/cross_source/evasion)
│   ├── sample/          # Small bundled sample CSV for CI / tests (committed)
│   │   └── requests_sample.csv
│   ├── SOURCES.md       # Dataset URLs, provenance, and licenses
│   └── download.py      # Automated dataset downloader
├── augment/             # Evasion payload mutation engine (Stage 3)
│   ├── mutate.py        # Seeded deterministic Family A (seen) and Family B (unseen) mutations
│   ├── llm_variants.py  # Optional LLM-assisted variant generator (off by default)
│   └── README.md        # Detailed mutation families and normalisation absorption specs
├── features.py          # TF-IDF char n-grams (2-5) + 8 lexical features extractor
├── prepare_augmented.py # Generates train_augmented.csv, evasion_test.csv, benign_obfuscated_test.csv
├── evaluate.py          # Metric calculations, threshold calibration, and 1,000-run latency profiler
├── train.py             # Model training (supports --augmented flag for robust retraining)
├── cross_eval.py        # Cross-source generalization evaluator across 5 corpus subsets
├── measure_rules_fpr.py # Rule-only false-positive rate evaluation harness
├── models/              # Exported production model artefacts & metadata
│   ├── model.joblib     # Active robust model (symbolic link or copy of model_augmented.joblib)
│   ├── model_plain.joblib # Stage 2 baseline model (saved for comparative evaluation)
│   ├── model_augmented.joblib # Stage 3 robust augmented model
│   └── metadata.json    # Calibrated threshold (0.940), library versions, and metrics
├── reports/             # Generated comparison reports
│   ├── model_comparison.md # 4-model evaluation table across val, test, and cross-source test
│   ├── robustness_report.md # Plain vs Augmented robustness matrix across evasion sets
│   ├── cross_source.md  # Detailed cross-dataset evaluation across all 5 corpus sources
│   └── rules_fpr.md     # 29-rule false-positive rate audit report
├── notebooks/           # Jupyter exploration & evaluation notebooks
│   └── 01_eda.ipynb     # Exploratory Data Analysis skeleton
├── SCHEMA.md            # Canonical column schemas & anti-leakage rules
└── requirements.txt     # Python ML dependencies
```

---

## Model Selection Rule & Winning Production Model

### Pre-Registered Selection Rule
> The winning model is selected based on the **highest malicious-class F1 score on the Validation set**, subject to:
> 1. Single-request p95 inference latency $\le$ **10.0 ms**
> 2. Validation False Positive Rate (FPR) $\le$ **2.5%**
> 
> *Ties are broken by smaller serialized model size and lower latency.*

### Production Model: Logistic Regression
- **Algorithm**: `LogisticRegression(C=1.0, max_iter=500, solver='lbfgs')`
- **Features**: Character n-grams (2–5, `char_wb`, `max_features=50,000`) + 8 scaled lexical statistical features.
- **Calibrated Threshold**: **`0.26`** (calibrated on Validation set to maximize F1 while bounding FPR).
- **Test Set F1 Score**: **`0.9995`** (Recall: `1.0000`, Precision: `0.9990`)
- **Test Set False Positive Rate**: **`0.43%`** (only 1 false positive out of 235 clean web samples)
- **Single-Request Inference Latency**: Median = **`1.39 ms`**, p95 = **`2.00 ms`** (well below the $\le 10$ ms budget)
- **Serialized Model Size**: **`2.01 MB`**

Detailed 4-model comparison results are in [`ml/reports/model_comparison.md`](reports/model_comparison.md).

---

## Step-by-Step ML Pipeline Workflow

### 1. Dataset Acquisition
```bash
make data
# Or manually:
python ml/data/download.py --dataset all
python ml/prepare.py
```
This fetches SecLists (SQLi, XSS) and CSIC 2010 (normal + anomalous), passes every payload through `waf_common.normalizer` (eliminating train/serve skew), deduplicates, and produces stratified splits (`train.csv`, `val.csv`, `test.csv`) plus held-out `cross_source_test.csv`.

### 2. Model Training & Comparison
```bash
make train
# Or manually:
python ml/train.py
```
Trains Logistic Regression, Calibrated Linear SVM, Decision Tree, and Random Forest. Calculates metrics across validation and test sets, profiles single-request latency over 1,000 runs, calibrates decision thresholds, saves `model.joblib` and `metadata.json`, and outputs `ml/reports/model_comparison.md`.

### 3. Rule False-Positive Rate Evaluation
```bash
python ml/measure_rules_fpr.py
```
Runs all 29 OWASP-style rules against 1,565 clean requests from CSIC 2010 and generates `ml/reports/rules_fpr.md` (Achieved Rule FPR: **0.00%**).

---

## Anti-Leakage Golden Rules
1. **Split before augmentation**: Never apply mutation or synthetic augmentation before dataset splitting.
2. **Train-only fitting**: The vectorizer and standard scalers are fitted exclusively on `train.csv`.
3. **Validation-only threshold tuning**: Optimal detection thresholds are calibrated on `val.csv` and never tuned on `test.csv`.
4. **Held-out cross-dataset source**: CSIC anomalous traffic is held out completely as `cross_source_test.csv` to evaluate generalizability (G6) without information leakage.
