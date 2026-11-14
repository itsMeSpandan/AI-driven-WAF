"""
Dataset preparation, canonical normalisation, deduplication, and splitting.
Implements Stage 2 Task 1 per TRD 2.3 & STAGES.md:
  - Uses shared `waf_common.normalizer` to guarantee zero train/serve skew
  - Ingests multiple distinct malicious sources (SecLists SQLi/XSS) and benign sources (CSIC + Synthetic)
  - Strict anti-leakage splitting: Split before any augmentation
  - Reserves held-out cross-dataset source (`cross_source_test.csv`)
  - Generates STATS.md summary documentation
"""

from __future__ import annotations

import hashlib
import random
import re
import sys
import urllib.parse
from pathlib import Path
from typing import Dict, List, Tuple

import pandas as pd
from sklearn.model_selection import train_test_split

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from waf_common.normalizer import normalise_request

RAW_DIR = REPO_ROOT / "ml" / "data" / "raw"
PROCESSED_DIR = REPO_ROOT / "ml" / "data" / "processed"


def parse_csic_block(block: str) -> Tuple[str, str, str, Dict[str, str], bytes]:
    """Parse a raw CSIC HTTP request block into method, path, query, headers, and body."""
    lines = block.strip().splitlines()
    if not lines:
        return "GET", "/", "", {}, b""

    # Request line: METHOD URL PROTOCOL
    req_line = lines[0].strip().split()
    method = req_line[0] if len(req_line) > 0 else "GET"
    raw_url = req_line[1] if len(req_line) > 1 else "/"

    parsed_url = urllib.parse.urlparse(raw_url)
    path = parsed_url.path or "/"
    query_string = parsed_url.query or ""

    headers: Dict[str, str] = {}
    body_lines: List[str] = []
    in_body = False

    for line in lines[1:]:
        if not in_body:
            if line.strip() == "":
                in_body = True
            elif ":" in line:
                hk, hv = line.split(":", 1)
                headers[hk.strip().lower()] = hv.strip()
        else:
            body_lines.append(line)

    body_bytes = "\n".join(body_lines).encode("utf-8", errors="replace")
    return method, path, query_string, headers, body_bytes


def classify_csic_anomalous_payload(text: str) -> str:
    """Classify anomalous CSIC payload into sqli, xss, or bot_anomaly."""
    t = text.lower()
    if any(k in t for k in ["select", "union", "drop", "' or '", "1=1", "insert into", "exec", "declare"]):
        return "sqli"
    elif any(k in t for k in ["<script", "alert(", "javascript:", "onerror=", "onload=", "<img", "<svg"]):
        return "xss"
    return "bot_anomaly"


def generate_synthetic_benign(count: int = 1500) -> List[Dict[str, str]]:
    """Generate realistic application traffic modeling OWASP Juice Shop / ecommerce apps."""
    random.seed(42)
    benign_templates = [
        ("GET", "/products", "category=books&page={page}&sort=price_asc", {}, b""),
        ("GET", "/products/{id}", "", {}, b""),
        ("GET", "/api/user/profile", "", {"user-agent": "Mozilla/5.0"}, b""),
        ("GET", "/cart", "", {}, b""),
        ("POST", "/cart/add", "", {"content-type": "application/json"}, b'{{"product_id": {id}, "quantity": {qty}}}'),
        ("POST", "/checkout", "", {"content-type": "application/json"}, b'{{"payment": "credit_card", "currency": "USD"}}'),
        ("GET", "/rest/products/search", "q={keyword}&limit=20", {}, b""),
        ("POST", "/contact", "", {"content-type": "application/x-www-form-urlencoded"}, b"name=Alice&message=Product+inquiry"),
        ("GET", "/assets/app.js", "", {}, b""),
        ("GET", "/assets/style.css", "", {}, b""),
        ("GET", "/health", "", {}, b""),
        ("GET", "/categories/electronics", "filter=in_stock", {}, b""),
    ]

    keywords = ["shoes", "tshirt", "laptop", "monitor", "coffee", "desk", "phone", "jacket", "cable", "mouse"]
    records = []

    for _ in range(count):
        tmpl_method, tmpl_path, tmpl_qs, headers, tmpl_body = random.choice(benign_templates)
        pid = random.randint(1, 500)
        page = random.randint(1, 10)
        qty = random.randint(1, 5)
        kw = random.choice(keywords)

        path = tmpl_path.format(id=pid)
        qs = tmpl_qs.format(page=page, keyword=kw)
        body = tmpl_body.replace(b"{id}", str(pid).encode()).replace(b"{qty}", str(qty).encode())

        norm = normalise_request(
            method=tmpl_method,
            path=path,
            query_string=qs,
            headers=headers,
            body_bytes=body,
        )

        records.append({
            "text": norm.canonical_text,
            "label": 0,
            "attack_type": "benign",
            "source": "synthetic_app",
        })

    return records


def ingest_all_datasets() -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Ingest, canonicalize, and label all raw datasets."""
    primary_records: List[Dict[str, str]] = []
    cross_source_records: List[Dict[str, str]] = []

    # 1. SecLists SQL Injection Payloads
    sqli_files = ["seclists_sqli_generic.txt", "seclists_sqli_auth_bypass.txt"]
    for fname in sqli_files:
        fpath = RAW_DIR / fname
        if fpath.exists():
            lines = [l.strip() for l in fpath.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip() and not l.startswith("#")]
            for p in lines:
                # Embed payload in query string and form body to reflect real attack vectors
                norm_get = normalise_request(method="GET", path="/rest/products/search", query_string=f"q={urllib.parse.quote(p)}")
                primary_records.append({"text": norm_get.canonical_text, "label": 1, "attack_type": "sqli", "source": "seclists"})

                norm_post = normalise_request(method="POST", path="/rest/user/login", headers={"content-type": "application/json"}, body_bytes=f'{{"user": "admin", "query": "{p}"}}'.encode("utf-8", errors="replace"))
                primary_records.append({"text": norm_post.canonical_text, "label": 1, "attack_type": "sqli", "source": "seclists"})

    # 2. SecLists XSS Payloads
    xss_files = ["seclists_xss_portswigger.txt", "seclists_xss_jhaddix.txt"]
    for fname in xss_files:
        fpath = RAW_DIR / fname
        if fpath.exists():
            lines = [l.strip() for l in fpath.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip() and not l.startswith("#")]
            for p in lines:
                norm_get = normalise_request(method="GET", path="/feedback", query_string=f"msg={urllib.parse.quote(p)}")
                primary_records.append({"text": norm_get.canonical_text, "label": 1, "attack_type": "xss", "source": "seclists"})

    # 3. CSIC 2010 Normal Requests (Benign)
    csic_normal_path = RAW_DIR / "csic_normal.txt"
    if csic_normal_path.exists():
        raw_text = csic_normal_path.read_text(encoding="latin-1", errors="ignore")
        blocks = raw_text.split("\n\n\n")
        for b in blocks:
            if not b.strip():
                continue
            m, p, q, h, body = parse_csic_block(b)
            norm = normalise_request(method=m, path=p, query_string=q, headers=h, body_bytes=body)
            primary_records.append({"text": norm.canonical_text, "label": 0, "attack_type": "benign", "source": "csic2010"})

    # 4. Synthetic Benign Requests
    primary_records.extend(generate_synthetic_benign(count=1500))

    # 5. CSIC 2010 Anomalous Requests (RESERVED for held-out cross_source_test)
    csic_anom_path = RAW_DIR / "csic_anomalous.txt"
    if csic_anom_path.exists():
        raw_text = csic_anom_path.read_text(encoding="latin-1", errors="ignore")
        blocks = raw_text.split("\n\n\n")
        for b in blocks:
            if not b.strip():
                continue
            m, p, q, h, body = parse_csic_block(b)
            norm = normalise_request(method=m, path=p, query_string=q, headers=h, body_bytes=body)
            atype = classify_csic_anomalous_payload(norm.canonical_text)
            cross_source_records.append({
                "text": norm.canonical_text,
                "label": 1,
                "attack_type": atype,
                "source": "csic2010_anomalous",
            })

    df_primary = pd.DataFrame(primary_records)
    df_cross = pd.DataFrame(cross_source_records)
    return df_primary, df_cross


def clean_and_deduplicate(df: pd.DataFrame) -> Tuple[pd.DataFrame, int]:
    """Remove empty strings, exact duplicates, and near-duplicate text hashes."""
    initial_count = len(df)
    # Drop empty or whitespace-only
    df = df[df["text"].str.strip().str.len() > 3].copy()

    # Exact text deduplication
    df = df.drop_duplicates(subset=["text"]).copy()

    # Hash-based near deduplication
    df["hash"] = df["text"].apply(lambda t: hashlib.md5(re.sub(r"\d+", "0", t).encode("utf-8")).hexdigest())
    df = df.drop_duplicates(subset=["hash"]).drop(columns=["hash"]).copy()

    removed = initial_count - len(df)
    return df, removed


def prepare_datasets():
    print("[*] Ingesting and canonicalizing datasets...")
    df_primary, df_cross = ingest_all_datasets()

    print(f"    Raw primary samples      : {len(df_primary)}")
    print(f"    Raw cross-source samples : {len(df_cross)}")

    # Clean both
    df_primary, rem_prim = clean_and_deduplicate(df_primary)
    df_cross, rem_cross = clean_and_deduplicate(df_cross)

    print(f"[+] Deduplication complete: removed {rem_prim} primary duplicates, {rem_cross} cross duplicates.")

    # Remove any cross-source samples that overlap with primary corpus to prevent leakage
    overlap_texts = set(df_primary["text"]) & set(df_cross["text"])
    if overlap_texts:
        print(f"[*] Purging {len(overlap_texts)} cross-contamination samples shared between primary and cross-source.")
        df_cross = df_cross[~df_cross["text"].isin(overlap_texts)].copy()

    print(f"    Clean primary corpus     : {len(df_primary)}")
    print(f"    Clean cross-source corpus: {len(df_cross)}")

    # Stratified Train/Val/Test Split (70% train, 15% val, 15% test)
    # Fixed seed for reproducibility
    train_df, temp_df = train_test_split(
        df_primary,
        test_size=0.30,
        random_state=42,
        stratify=df_primary["attack_type"],
    )

    val_df, test_df = train_test_split(
        temp_df,
        test_size=0.50,
        random_state=42,
        stratify=temp_df["attack_type"],
    )

    train_df = train_df.assign(split="train")
    val_df = val_df.assign(split="val")
    test_df = test_df.assign(split="test")
    df_cross = df_cross.assign(split="cross_source_test")

    # Anti-leakage verification: Ensure zero overlap between train and any evaluation set
    train_texts = set(train_df["text"])
    assert not (train_texts & set(val_df["text"])), "Leakage detected: train and val overlap!"
    assert not (train_texts & set(test_df["text"])), "Leakage detected: train and test overlap!"
    assert not (train_texts & set(df_cross["text"])), "Leakage detected: train and cross_source_test overlap!"
    print("[+] Anti-leakage check PASSED: Zero overlap between training and evaluation splits.")

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    train_df.to_csv(PROCESSED_DIR / "train.csv", index=False)
    val_df.to_csv(PROCESSED_DIR / "val.csv", index=False)
    test_df.to_csv(PROCESSED_DIR / "test.csv", index=False)
    df_cross.to_csv(PROCESSED_DIR / "cross_source_test.csv", index=False)

    print(f"[+] Saved processed datasets to {PROCESSED_DIR}")

    # Generate STATS.md
    generate_stats_markdown(train_df, val_df, test_df, df_cross)


def generate_stats_markdown(train_df: pd.DataFrame, val_df: pd.DataFrame, test_df: pd.DataFrame, cross_df: pd.DataFrame):
    """Write STATS.md documenting sample counts, class balance, and length distributions."""
    stats_file = PROCESSED_DIR / "STATS.md"

    def get_split_stats(df: pd.DataFrame, name: str) -> dict:
        lengths = df["text"].apply(len)
        return {
            "split": name,
            "total": len(df),
            "benign": (df["label"] == 0).sum(),
            "malicious": (df["label"] == 1).sum(),
            "sqli": (df["attack_type"] == "sqli").sum(),
            "xss": (df["attack_type"] == "xss").sum(),
            "other": (df["attack_type"].isin(["bot_anomaly", "other_anomaly"])).sum(),
            "len_p50": int(lengths.median()),
            "len_p95": int(lengths.quantile(0.95)),
            "sources": ", ".join(sorted(df["source"].unique())),
        }

    all_stats = [
        get_split_stats(train_df, "Train (70%)"),
        get_split_stats(val_df, "Validation (15%)"),
        get_split_stats(test_df, "Test (15%)"),
        get_split_stats(cross_df, "Held-Out Cross Source"),
    ]

    lines = [
        "# Processed Dataset Statistics (Stage 2)",
        "",
        "> Generated automatically by `ml/prepare.py`. Follows the strict golden rule: split before augmentation.",
        "",
        "## 1. Partition Overview",
        "",
        "| Split | Total Samples | Benign | Malicious | SQLi | XSS | Other Anomaly | Median Len (p50) | p95 Len | Data Sources |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]

    for s in all_stats:
        lines.append(
            f"| **{s['split']}** | {s['total']:,} | {s['benign']:,} | {s['malicious']:,} | {s['sqli']:,} | {s['xss']:,} | {s['other']:,} | {s['len_p50']} B | {s['len_p95']} B | {s['sources']} |"
        )

    lines.extend([
        "",
        "## 2. Integrity & Zero-Leakage Guarantee",
        "- All inputs canonicalized via shared `waf_common.normalizer.normalise_request` before feature extraction.",
        "- Duplicates and near-duplicate text hashes removed.",
        "- Stratified split on attack taxonomy using seed `random_state=42`.",
        "- Cross-split intersection verified: `|Train ∩ Val| = 0`, `|Train ∩ Test| = 0`, `|Train ∩ CrossSource| = 0`.",
    ])

    stats_file.write_text("\n".join(lines), encoding="utf-8")
    print(f"[+] Documented dataset breakdown in {stats_file}")


if __name__ == "__main__":
    prepare_datasets()
