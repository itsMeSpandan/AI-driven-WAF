"""
Script to automatically extract benchmark numbers from eval/results/*.json
and generate verified markdown tables for docs/FINAL_REPORT.md.
Ensures zero hand-typed metric drift.
"""

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DETECTION_JSON = REPO_ROOT / "eval" / "results" / "detection.json"
PERF_JSON = REPO_ROOT / "eval" / "results" / "performance.json"
REPORT_MD = REPO_ROOT / "docs" / "FINAL_REPORT.md"


def generate_tables() -> dict[str, str]:
    if not DETECTION_JSON.exists() or not PERF_JSON.exists():
        raise FileNotFoundError("Evaluation JSON files missing! Run 'make eval' first.")

    det_data = json.loads(DETECTION_JSON.read_text(encoding="utf-8"))
    perf_data = json.loads(PERF_JSON.read_text(encoding="utf-8"))

    # Table 1: Detection Headline Matrix
    t1_lines = [
        "| Evaluation Partition | Evaluation Size ($N$) | Engine Configuration | Recall (Wilson 95% CI) | False Positive Rate (95% CI) | F1-Score | Block Rate |",
        "|:---|:---:|:---|:---:|:---:|:---:|:---:|",
    ]
    res = det_data["results"]
    for c_key, c_info in res.items():
        c_title = c_info["display_name"]
        n_size = c_info["total_requests"]
        cfgs = c_info["configs"]
        for cfg_key in ["modsec_pl1", "ai_waf_rules_only", "ai_waf_ml_only", "ai_waf_hybrid"]:
            if cfg_key in cfgs:
                d = cfgs[cfg_key]
                r_ci = d["recall_ci_95"]
                f_ci = d["fpr_ci_95"]
                rec_str = f"**{d['recall']*100:.2f}%** [{r_ci[0]*100:.1f}–{r_ci[1]*100:.1f}%]" if cfg_key == "ai_waf_hybrid" else f"{d['recall']*100:.2f}% [{r_ci[0]*100:.1f}–{r_ci[1]*100:.1f}%]"
                fpr_str = f"{d['fpr']*100:.2f}% [{f_ci[0]*100:.1f}–{f_ci[1]*100:.1f}%]"
                f1_str = f"{d['f1']:.4f}"
                blk_str = f"{d['block_rate']*100:.1f}%"
                cfg_display = f"`{cfg_key}`"
                t1_lines.append(f"| {c_title} | {n_size:,} | {cfg_display} | {rec_str} | {fpr_str} | {f1_str} | {blk_str} |")

    # Table 2: Latency & Concurrency Scaling
    t2_lines = [
        "| Concurrency Level | Engine Configuration | Sustained RPS | p50 Latency (ms) | p95 Latency (ms) (Spread) | Overhead vs Direct (ms, %) |",
        "|:---:|:---|:---:|:---:|:---:|:---:|",
    ]
    mixed = perf_data["workloads"]["mixed_90_10"]
    for c_key in ["concurrency_10", "concurrency_50", "concurrency_100"]:
        c_num = c_key.replace("concurrency_", "")
        c_data = mixed[c_key]
        for cfg_key in ["direct", "ai_waf_rules", "ai_waf_rules_ml", "ai_waf_full_explainer", "modsec_pl1"]:
            d = c_data[cfg_key]
            t2_lines.append(
                f"| {c_num} Clients | `{cfg_key}` | {d['rps']:,.1f} | {d['p50_ms']:.2f} | {d['p95_ms']:.2f} (±{d['p95_spread']:.2f}) | +{d['overhead_ms']:.2f}ms (+{d['overhead_pct']:.1f}%) |"
            )

    # Table 3: Overlap Analysis
    t3_lines = [
        "| Evaluation Partition | Total Attacks ($N$) | Both Engines Caught | Only AI-WAF Caught | Only ModSec Caught | Neither Caught | Hypothetical Serial Recall |",
        "|:---|:---:|:---:|:---:|:---:|:---:|:---:|",
    ]
    overlap = det_data.get("overlap_analysis", {})
    for c_key, o in overlap.items():
        tot = o["total_attacks"]
        both_pct = (o["both_blocked"] / tot * 100) if tot > 0 else 0.0
        ai_pct = (o["only_ai_blocked"] / tot * 100) if tot > 0 else 0.0
        ms_pct = (o["only_modsec_blocked"] / tot * 100) if tot > 0 else 0.0
        none_pct = (o["neither_blocked"] / tot * 100) if tot > 0 else 0.0
        serial_pct = o["serial_combination_recall"] * 100
        t3_lines.append(
            f"| `{c_key}` | {tot:,} | {o['both_blocked']} ({both_pct:.1f}%) | "
            f"**{o['only_ai_blocked']} ({ai_pct:.1f}%)** | {o['only_modsec_blocked']} ({ms_pct:.1f}%) | "
            f"{o['neither_blocked']} ({none_pct:.1f}%) | **{serial_pct:.2f}%** |"
        )

    return {
        "detection_table": "\n".join(t1_lines),
        "performance_table": "\n".join(t2_lines),
        "overlap_table": "\n".join(t3_lines),
    }


if __name__ == "__main__":
    tables = generate_tables()
    print("[+] Successfully generated verified report tables from evaluation JSONs:")
    print(f"    - Detection table rows: {len(tables['detection_table'].splitlines())}")
    print(f"    - Performance table rows: {len(tables['performance_table'].splitlines())}")
    print(f"    - Overlap table rows: {len(tables['overlap_table'].splitlines())}")
