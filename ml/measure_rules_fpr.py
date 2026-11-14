"""
Measures and reports the rule-only False Positive Rate (FPR) on clean benign traffic.
Implements Stage 2 Task 4 requirement for ml/reports/rules_fpr.md.
"""

from __future__ import annotations

import datetime
import sys
from pathlib import Path
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from gateway.rules import RULES, evaluate_rules

PROCESSED_DIR = REPO_ROOT / "ml" / "data" / "processed"
REPORTS_DIR = REPO_ROOT / "ml" / "reports"


def measure_rule_fpr():
    dfs = []
    for split in ["train", "val", "test"]:
        path = PROCESSED_DIR / f"{split}.csv"
        if path.exists():
            df = pd.read_csv(path)
            dfs.append(df[df["label"] == 0])

    if not dfs:
        print("[!] No processed datasets found to measure FPR.")
        return

    benign_df = pd.concat(dfs, ignore_index=True)
    total_benign = len(benign_df)
    print(f"[*] Evaluating {len(RULES)} rules on {total_benign} verified benign samples...")

    fp_hits = []
    rule_hit_counts = {r.id: 0 for r in RULES}

    for idx, row in benign_df.iterrows():
        text = str(row["text"])
        hit = evaluate_rules(text)
        if hit is not None:
            rule_hit_counts[hit.rule_id] += 1
            fp_hits.append({
                "index": idx,
                "text": text,
                "rule_id": hit.rule_id,
                "severity": hit.severity,
                "description": hit.description,
            })

    total_fps = len(fp_hits)
    rule_fpr = (total_fps / total_benign) * 100.0 if total_benign > 0 else 0.0

    print(f"[+] Total Benign Samples : {total_benign}")
    print(f"[+] False Positive Hits  : {total_fps}")
    print(f"[+] Rule-Only FPR        : {rule_fpr:.2f}%")

    # Generate Markdown Report
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    report_file = REPORTS_DIR / "rules_fpr.md"

    lines = [
        "# Rule-Only Baseline False Positive Rate (FPR) Report",
        "",
        f"**Date:** {datetime.date.today().isoformat()}",
        f"**Corpus Size:** {total_benign:,} verified benign requests",
        f"**Active Rules:** {len(RULES)} signatures",
        f"**Measured Rule-Only FPR:** `{rule_fpr:.2f}%` ({total_fps} / {total_benign})",
        "",
        "---",
        "",
        "## 1. Rule Hit Breakdown on Benign Traffic",
        "",
        "| Rule ID | Category | Severity | Description | False Hits | Hit Rate on Benign |",
        "|---|---|---|---|---|---|",
    ]

    for r in RULES:
        hits = rule_hit_counts[r.id]
        pct = (hits / total_benign * 100.0) if total_benign > 0 else 0.0
        lines.append(f"| `{r.id}` | {r.category} | {r.severity} | {r.description} | {hits} | {pct:.2f}% |")

    lines.extend([
        "",
        "## 2. False Positive Samples Analysis",
        "",
    ])

    if fp_hits:
        lines.append("| Sample Index | Rule Hit | Matched Text Snippet |")
        lines.append("|---|---|---|")
        for h in fp_hits[:10]:  # Show top 10
            snippet = h['text'][:90].replace("|", "\\|")
            lines.append(f"| {h['index']} | `{h['rule_id']}` | `{snippet}` |")
    else:
        lines.append("Zero false positives were observed on the clean benign corpus. The rule set maintains high specificity.")

    lines.extend([
        "",
        "## 3. Findings & Mitigation",
        "- The hybrid architecture utilizes the rule layer as a cheap first-pass filter for unambiguous attack syntax.",
        "- Subtler, ambiguous requests with non-zero threat potential are delegated to the ML detector for nuanced probability scoring.",
    ])

    report_file.write_text("\n".join(lines), encoding="utf-8")
    print(f"[+] Saved rule FPR report to {report_file}")


if __name__ == "__main__":
    measure_rule_fpr()
