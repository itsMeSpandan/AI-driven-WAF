# Machine Learning Workspace

This directory contains the data preparation, augmentation, model training, and evaluation pipelines for the AI-Driven Web Application Firewall.

---

## Directory Structure

```
ml/
├── data/
│   ├── raw/             # Raw candidate datasets (gitignored)
│   ├── processed/       # Normalized & deduplicated datasets (gitignored)
│   ├── sample/          # Small bundled sample CSV for CI / tests (committed)
│   │   └── requests_sample.csv
│   ├── SOURCES.md       # Dataset URLs, provenance, and licenses
│   └── download.py      # Automated dataset downloader
├── augment/             # Payload mutation functions (evasion set generation)
├── models/              # Exported scikit-learn models & vectorizers (.joblib)
├── notebooks/           # Jupyter exploration & evaluation notebooks
│   └── 01_eda.ipynb     # Exploratory Data Analysis skeleton
├── SCHEMA.md            # Canonical column schemas & anti-leakage rules
└── requirements.txt     # Python ML dependencies
```

---

## Workflow (Stage 1 & Stage 2)

### 1. Dataset Acquisition
```bash
python ml/data/download.py --dataset all
```
Metadata and license documentation are tracked in [`ml/data/SOURCES.md`](data/SOURCES.md).

### 2. Exploratory Data Analysis
Open [`ml/notebooks/01_eda.ipynb`](notebooks/01_eda.ipynb) to inspect class distributions, character length profiles, and verify split integrity.

### 3. The Golden Rule
> **Split before augmentation.** See [`ml/SCHEMA.md`](SCHEMA.md) for data leakage prevention rules.
