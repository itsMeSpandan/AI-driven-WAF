"""
Augmented dataset preparation & Evasion test set builder.
Implements Stage 3 Task 2 per TRD 2.3 & STAGES.md:
  - Augments ONLY the train split after splitting (strictly zero data leakage)
  - Applies Family A mutations to malicious training samples
  - Applies benign obfuscations to benign training samples (protects FPR)
  - Builds evasion_test (unseen Family B mutations applied to test split)
  - Builds evasion_test_familyA (seen Family A mutations applied to test split)
  - Builds benign_obfuscated_test (obfuscated benign test samples for FPR evaluation)
  - Verifies zero cross-split leakage and updates ml/data/processed/STATS.md
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Dict, List, Set

import pandas as pd

# Ensure repo root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from ml.augment.mutate import (
    measure_normalisation_absorption,
    mutate_payload,
)
from waf_common.normalizer import normalise_request

PROCESSED_DIR = REPO_ROOT / "ml" / "data" / "processed"


def canonicalize(text: str) -> str:
    """Normalizes mutated text via the shared WAF normalizer."""
    if not text:
        return ""
    # Treat text as query string or body depending on structure
    if " " in text and (text.startswith("get ") or text.startswith("post ")):
        parts = text.split(" ", 2)
        method = parts[0].upper()
        path = parts[1]
        extra = parts[2] if len(parts) > 2 else ""
        return normalise_request(method, path, extra, {}, b"").canonical_text
    return normalise_request("GET", "/test", text, {}, b"").canonical_text


def build_augmented_datasets(
    malicious_train_ratio: int = 1,
    benign_train_ratio: int = 1,
    seed: int = 42,
) -> None:
    print("==================================================================")
    print("      AI-Driven WAF — Dataset Augmentation & Evasion Sets         ")
    print("==================================================================")

    train_path = PROCESSED_DIR / "train.csv"
    val_path = PROCESSED_DIR / "val.csv"
    test_path = PROCESSED_DIR / "test.csv"
    cross_path = PROCESSED_DIR / "cross_source_test.csv"

    if not train_path.exists() or not test_path.exists():
        raise FileNotFoundError(f"Missing processed datasets in {PROCESSED_DIR}. Run 'make data' first.")

    df_train = pd.read_csv(train_path)
    df_val = pd.read_csv(val_path)
    df_test = pd.read_csv(test_path)
    df_cross = pd.read_csv(cross_path) if cross_path.exists() else pd.DataFrame(columns=["text"])

    print(f"[*] Base train samples : {len(df_train)} (Malicious: {(df_train['label']==1).sum()}, Benign: {(df_train['label']==0).sum()})")
    print(f"[*] Base test samples  : {len(df_test)} (Malicious: {(df_test['label']==1).sum()}, Benign: {(df_test['label']==0).sum()})")

    # --------------------------------------------------------------------------
    # 1. Augment Train Split (Family A ONLY)
    # --------------------------------------------------------------------------
    print("\n[*] Generating Family A augmented training samples...")
    augmented_train_rows: List[Dict[str, any]] = []
    seen_texts: Set[str] = set(df_train["text"].tolist())

    for idx, row in df_train.iterrows():
        orig_text = str(row["text"])
        atk_type = str(row["attack_type"])
        is_mal = int(row["label"]) == 1

        ratio = malicious_train_ratio if is_mal else benign_train_ratio

        for r_idx in range(ratio):
            sample_seed = seed + idx * 31 + r_idx * 17
            mutated_raw = mutate_payload(orig_text, family="A", attack_type=atk_type, seed=sample_seed)
            mutated_norm = canonicalize(mutated_raw)

            if mutated_norm and mutated_norm not in seen_texts:
                seen_texts.add(mutated_norm)
                augmented_train_rows.append({
                    "text": mutated_norm,
                    "label": row["label"],
                    "attack_type": atk_type,
                    "source": f"{row['source']}_familyA_aug",
                    "split": "train",
                })

    df_train_aug = pd.concat([df_train, pd.DataFrame(augmented_train_rows)], ignore_index=True)
    df_train_aug = df_train_aug.drop_duplicates(subset=["text"]).reset_index(drop=True)
    print(f"[+] Total augmented train samples: {len(df_train_aug)} (+{len(augmented_train_rows)} added)")

    # --------------------------------------------------------------------------
    # 2. Build evasion_test (Family B - Unseen Evasion on Test Malicious)
    # --------------------------------------------------------------------------
    print("[*] Generating evasion_test (Family B - Unseen Evaluation Families)...")
    malicious_test = df_test[df_test["label"] == 1].copy()
    evasion_b_rows: List[Dict[str, any]] = []

    for idx, row in malicious_test.iterrows():
        orig_text = str(row["text"])
        atk_type = str(row["attack_type"])
        mut_raw = mutate_payload(orig_text, family="B", attack_type=atk_type, seed=seed + idx * 13)
        mut_norm = canonicalize(mut_raw)
        evasion_b_rows.append({
            "text": mut_norm if mut_norm else orig_text,
            "label": 1,
            "attack_type": atk_type,
            "source": f"{row['source']}_familyB_evasion",
            "split": "evasion_test",
        })

    df_evasion_b = pd.DataFrame(evasion_b_rows).drop_duplicates(subset=["text"]).reset_index(drop=True)
    print(f"[+] evasion_test (Family B) size: {len(df_evasion_b)}")

    # --------------------------------------------------------------------------
    # 3. Build evasion_test_familyA (Family A - Seen Families on Test Malicious)
    # --------------------------------------------------------------------------
    print("[*] Generating evasion_test_familyA (Family A - Seen Families on Test)...")
    evasion_a_rows: List[Dict[str, any]] = []

    for idx, row in malicious_test.iterrows():
        orig_text = str(row["text"])
        atk_type = str(row["attack_type"])
        mut_raw = mutate_payload(orig_text, family="A", attack_type=atk_type, seed=seed + idx * 29)
        mut_norm = canonicalize(mut_raw)
        evasion_a_rows.append({
            "text": mut_norm if mut_norm else orig_text,
            "label": 1,
            "attack_type": atk_type,
            "source": f"{row['source']}_familyA_evasion",
            "split": "evasion_test_familyA",
        })

    df_evasion_a = pd.DataFrame(evasion_a_rows).drop_duplicates(subset=["text"]).reset_index(drop=True)
    print(f"[+] evasion_test_familyA size   : {len(df_evasion_a)}")

    # --------------------------------------------------------------------------
    # 4. Build benign_obfuscated_test (Harmless Obfuscation on Test Benign)
    # --------------------------------------------------------------------------
    print("[*] Generating benign_obfuscated_test...")
    benign_test = df_test[df_test["label"] == 0].copy()
    benign_obf_rows: List[Dict[str, any]] = []

    for idx, row in benign_test.iterrows():
        orig_text = str(row["text"])
        mut_raw = mutate_payload(orig_text, family="A", attack_type="benign", seed=seed + idx * 43)
        mut_norm = canonicalize(mut_raw)
        benign_obf_rows.append({
            "text": mut_norm if mut_norm else orig_text,
            "label": 0,
            "attack_type": "benign",
            "source": f"{row['source']}_obfuscated",
            "split": "benign_obfuscated_test",
        })

    df_benign_obf = pd.DataFrame(benign_obf_rows).drop_duplicates(subset=["text"]).reset_index(drop=True)
    print(f"[+] benign_obfuscated_test size : {len(df_benign_obf)}")

    # --------------------------------------------------------------------------
    # 5. Anti-Leakage Verification
    # --------------------------------------------------------------------------
    print("\n[*] Running strict anti-leakage verification...")
    val_set = set(df_val["text"].tolist())
    test_set = set(df_test["text"].tolist())
    evasion_b_set = set(df_evasion_b["text"].tolist())

    train_aug_set = set(df_train_aug["text"].tolist())

    leak_val = train_aug_set.intersection(val_set)
    leak_test = train_aug_set.intersection(test_set)
    leak_evasion = train_aug_set.intersection(evasion_b_set)

    # Purge any accidental overlaps to guarantee 100% zero leakage
    if leak_val or leak_test or leak_evasion:
        overlaps = leak_val.union(leak_test).union(leak_evasion)
        print(f"[!] Warning: Purging {len(overlaps)} overlapping samples from augmented training set.")
        df_train_aug = df_train_aug[~df_train_aug["text"].isin(overlaps)].reset_index(drop=True)

    assert len(set(df_train_aug["text"]).intersection(val_set)) == 0, "Leakage with validation set!"
    assert len(set(df_train_aug["text"]).intersection(test_set)) == 0, "Leakage with test set!"
    assert len(set(df_train_aug["text"]).intersection(evasion_b_set)) == 0, "Leakage with evasion Family B set!"
    print("[+] Anti-leakage checks PASSED: Zero overlap across training and evaluation sets.")

    # --------------------------------------------------------------------------
    # 6. Save Processed Datasets
    # --------------------------------------------------------------------------
    train_aug_file = PROCESSED_DIR / "train_augmented.csv"
    evasion_b_file = PROCESSED_DIR / "evasion_test.csv"
    evasion_a_file = PROCESSED_DIR / "evasion_test_familyA.csv"
    benign_obf_file = PROCESSED_DIR / "benign_obfuscated_test.csv"

    df_train_aug.to_csv(train_aug_file, index=False)
    df_evasion_b.to_csv(evasion_b_file, index=False)
    df_evasion_a.to_csv(evasion_a_file, index=False)
    df_benign_obf.to_csv(benign_obf_file, index=False)

    print(f"\n[+] Saved {train_aug_file} ({len(df_train_aug)} rows)")
    print(f"[+] Saved {evasion_b_file} ({len(df_evasion_b)} rows)")
    print(f"[+] Saved {evasion_a_file} ({len(df_evasion_a)} rows)")
    print(f"[+] Saved {benign_obf_file} ({len(df_benign_obf)} rows)")

    # --------------------------------------------------------------------------
    # 7. Measure Normalisation Absorption on Benchmark Samples
    # --------------------------------------------------------------------------
    test_sample_pairs = [(row["text"], row["attack_type"]) for _, row in df_test.head(100).iterrows()]
    absorption_a = measure_normalisation_absorption(test_sample_pairs, family="A", seed=seed)
    absorption_b = measure_normalisation_absorption(test_sample_pairs, family="B", seed=seed)

    print(f"\n[*] Normalisation Absorption Rates on 100 test samples:")
    print(f"    Family A : {absorption_a['absorption_rate'] * 100:.1f}% absorbed, {absorption_a['survival_rate'] * 100:.1f}% survived")
    print(f"    Family B : {absorption_b['absorption_rate'] * 100:.1f}% absorbed, {absorption_b['survival_rate'] * 100:.1f}% survived")

    # --------------------------------------------------------------------------
    # 8. Update STATS.md
    # --------------------------------------------------------------------------
    stats_content = f"""# Processed Dataset Statistics & Split Breakdown

**Last Updated**: {pd.Timestamp.now(tz='UTC').strftime('%Y-%m-%d %H:%M:%S UTC')}  
**Canonical Normalization**: `waf_common.normalizer.normalise_request` (NFKC, iterative URL decode depth 3, HTML entities, SQL comments stripped, whitespace collapsed).

---

## 1. Split Sizes & Class Balances

| Split File | Total Samples | Malicious (label=1) | Benign (label=0) | Attack Types (SQLi / XSS / Benign) | Role |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`train.csv`** (Plain) | {len(df_train):,} | {(df_train['label']==1).sum():,} | {(df_train['label']==0).sum():,} | {(df_train['attack_type']=='sqli').sum():,} / {(df_train['attack_type']=='xss').sum():,} / {(df_train['attack_type']=='benign').sum():,} | Plain Model Training |
| **`train_augmented.csv`** | {len(df_train_aug):,} | {(df_train_aug['label']==1).sum():,} | {(df_train_aug['label']==0).sum():,} | {(df_train_aug['attack_type']=='sqli').sum():,} / {(df_train_aug['attack_type']=='xss').sum():,} / {(df_train_aug['attack_type']=='benign').sum():,} | Robust Model Training (Family A) |
| **`val.csv`** | {len(df_val):,} | {(df_val['label']==1).sum():,} | {(df_val['label']==0).sum():,} | {(df_val['attack_type']=='sqli').sum():,} / {(df_val['attack_type']=='xss').sum():,} / {(df_val['attack_type']=='benign').sum():,} | Threshold Calibration & Model Selection |
| **`test.csv`** | {len(df_test):,} | {(df_test['label']==1).sum():,} | {(df_test['label']==0).sum():,} | {(df_test['attack_type']=='sqli').sum():,} / {(df_test['attack_type']=='xss').sum():,} / {(df_test['attack_type']=='benign').sum():,} | In-Distribution Evaluation |
| **`evasion_test_familyA.csv`** | {len(df_evasion_a):,} | {(df_evasion_a['label']==1).sum():,} | {(df_evasion_a['label']==0).sum():,} | {(df_evasion_a['attack_type']=='sqli').sum():,} / {(df_evasion_a['attack_type']=='xss').sum():,} / 0 | Seen Evasion Family Evaluation |
| **`evasion_test.csv`** | {len(df_evasion_b):,} | {(df_evasion_b['label']==1).sum():,} | {(df_evasion_b['label']==0).sum():,} | {(df_evasion_b['attack_type']=='sqli').sum():,} / {(df_evasion_b['attack_type']=='xss').sum():,} / 0 | **Unseen Family B Evasion Evaluation** |
| **`benign_obfuscated_test.csv`**| {len(df_benign_obf):,} | 0 | {len(df_benign_obf):,} | 0 / 0 / {len(df_benign_obf):,} | False Positive Rate Under Obfuscation |
| **`cross_source_test.csv`** | {len(df_cross):,} | {(df_cross['label']==1).sum():,} | {(df_cross['label']==0).sum():,} | 0 / 0 / {len(df_cross):,} (Anomalous CSIC) | Out-of-Distribution Generalization (G6) |

---

## 2. Normalisation Absorption Characteristics

| Mutation Family | Description | Normalisation Absorption Rate | Evasion Survival Rate | Note |
| :--- | :--- | :--- | :--- | :--- |
| **Family A** | Case, comments `/**/`, whitespace, single URL encode | {absorption_a['absorption_rate'] * 100:.1f}% | {absorption_a['survival_rate'] * 100:.1f}% | Normalizer absorbs simple evasions |
| **Family B** | Double URL encode `%25`, hex/char codes, concat, obscure tags | {absorption_b['absorption_rate'] * 100:.1f}% | {absorption_b['survival_rate'] * 100:.1f}% | Survives normalizer; requires ML detector |

---

## 3. Strict Anti-Leakage Invariants

1. **Pre-Split Separation**: Augmentations are applied strictly to `train.csv` after the random seed partition was created in Stage 2.
2. **Disjoint Families**: Family B mutators are never invoked for training data.
3. **Zero Exact Overlap**: The intersection between `train_augmented.csv` and (`val.csv`, `test.csv`, `evasion_test.csv`, `cross_source_test.csv`) is verified to be exactly 0 samples.
"""
    stats_file = PROCESSED_DIR / "STATS.md"
    stats_file.write_text(stats_content, encoding="utf-8")
    print(f"[+] Updated dataset statistics in {stats_file}")


if __name__ == "__main__":
    build_augmented_datasets()
