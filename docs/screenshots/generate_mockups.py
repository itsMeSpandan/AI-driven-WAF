"""
Generates visual screenshot preview diagrams for docs/screenshots/:
  1. dashboard_overview.png
  2. explanation_drawer.png
  3. model_eval_page.png
"""

from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

SCREENSHOTS_DIR = Path(__file__).resolve().parent
SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)

plt.rcParams.update({
    "font.family": "sans-serif",
    "font.size": 10,
})

def create_dashboard_mockup():
    fig = plt.figure(figsize=(14, 8), dpi=200, facecolor="#0f172a")
    gs = fig.add_gridspec(3, 3, hspace=0.35, wspace=0.25)

    # Header / KPI Cards
    kpis = [
        ("Total Inspected", "14,892 reqs", "#38bdf8"),
        ("Threats Blocked", "2,140 (14.4%)", "#ef4444"),
        ("Mean Latency", "1.82 ms", "#10b981"),
        ("Active Mode", "BLOCK (tau=0.94)", "#f59e0b"),
    ]
    for i, (title, val, color) in enumerate(kpis):
        ax_kpi = fig.add_subplot(gs[0, 0:2 if i < 2 else 2:3])
        if i == 0:
            ax_kpi = fig.add_subplot(gs[0, 0])
        elif i == 1:
            ax_kpi = fig.add_subplot(gs[0, 1])
        elif i == 2:
            ax_kpi = fig.add_subplot(gs[0, 2])
        
        ax_kpi.set_facecolor("#1e293b")
        ax_kpi.text(0.1, 0.65, title, color="#94a3b8", fontsize=10, transform=ax_kpi.transAxes)
        ax_kpi.text(0.1, 0.25, val, color=color, fontsize=14, fontweight="bold", transform=ax_kpi.transAxes)
        ax_kpi.set_xticks([])
        ax_kpi.set_yticks([])
        for spine in ax_kpi.spines.values():
            spine.set_color("#334155")

    # Time-Series Traffic Chart
    ax_time = fig.add_subplot(gs[1, 0:2])
    ax_time.set_facecolor("#1e293b")
    times = np.arange(20)
    traffic = np.random.normal(120, 15, size=20)
    threats = np.random.normal(18, 5, size=20)
    ax_time.plot(times, traffic, color="#38bdf8", lw=2, label="Clean Traffic")
    ax_time.fill_between(times, traffic, color="#38bdf8", alpha=0.15)
    ax_time.plot(times, threats, color="#ef4444", lw=2, label="Blocked Threats")
    ax_time.fill_between(times, threats, color="#ef4444", alpha=0.25)
    ax_time.set_title("Real-Time Traffic vs Threats (Requests / Sec)", color="#f8fafc", fontsize=11, loc="left")
    ax_time.legend(facecolor="#1e293b", edgecolor="#334155", labelcolor="#f8fafc", fontsize=8)
    ax_time.tick_params(colors="#94a3b8")
    for spine in ax_time.spines.values():
        spine.set_color("#334155")

    # Attack Breakdown Donut
    ax_pie = fig.add_subplot(gs[1, 2])
    ax_pie.set_facecolor("#1e293b")
    sizes = [48, 32, 12, 8]
    colors = ["#ef4444", "#f97316", "#a855f7", "#eab308"]
    labels = ["SQLi", "XSS", "Evasion", "LFI/RCE"]
    wedges, texts, autotexts = ax_pie.pie(
        sizes, labels=labels, colors=colors, autopct="%1.0f%%",
        startangle=90, textprops=dict(color="#f8fafc", fontsize=8),
        wedgeprops=dict(width=0.4, edgecolor="#0f172a")
    )
    for at in autotexts:
        at.set_color("#0f172a")
        at.set_weight("bold")
    ax_pie.set_title("Threat Vector Distribution", color="#f8fafc", fontsize=11)

    # Request Feed Preview Table
    ax_table = fig.add_subplot(gs[2, :])
    ax_table.set_facecolor("#1e293b")
    ax_table.text(0.02, 0.85, "Live Request Inspection Feed", color="#f8fafc", fontsize=11, fontweight="bold", transform=ax_table.transAxes)
    feed_items = [
        ("10:41:02", "POST", "/rest/user/login", "user=admin' OR 1=1--", "403 BLOCKED", "SQLi (Tautology)", "#ef4444"),
        ("10:41:01", "GET", "/rest/products/search", "q=laptop%20stand", "200 ALLOWED", "Benign", "#10b981"),
        ("10:40:59", "GET", "/api/Feedbacks", "msg=<script>alert(1)</script>", "403 BLOCKED", "XSS (Stored)", "#ef4444"),
        ("10:40:58", "POST", "/api/v1/checkout", "cart_id=8192&token=0x6164", "403 BLOCKED", "Evasion (Hex)", "#ef4444"),
    ]
    y_pos = 0.65
    for ts, m, path, payload, status, cat, col in feed_items:
        line_str = f"[{ts}]  {m:<4}  {path:<24}  {payload:<32}  {cat:<18}  {status}"
        ax_table.text(0.02, y_pos, line_str, color=col if "BLOCKED" in status else "#94a3b8", fontfamily="monospace", fontsize=9, transform=ax_table.transAxes)
        y_pos -= 0.18

    ax_table.set_xticks([])
    ax_table.set_yticks([])
    for spine in ax_table.spines.values():
        spine.set_color("#334155")

    plt.suptitle("AI-WAF Live Analytics Dashboard (Overview)", color="#f8fafc", fontsize=14, y=0.98)
    out = SCREENSHOTS_DIR / "dashboard_overview.png"
    plt.savefig(out, dpi=200, facecolor=fig.get_facecolor(), bbox_inches="tight")
    plt.close()
    print(f"[+] Created {out}")


def create_explanation_drawer_mockup():
    fig = plt.figure(figsize=(10, 7), dpi=200, facecolor="#0f172a")
    ax = fig.add_subplot(111)
    ax.set_facecolor("#1e293b")

    # Drawer title
    ax.text(0.05, 0.92, "Request Explanation Drawer — Threat Details", color="#f8fafc", fontsize=13, fontweight="bold")
    ax.text(0.05, 0.86, "Request ID: req-8f192b | Timestamp: 2026-11-15T10:41:02Z | Verdict: BLOCKED (403)", color="#94a3b8", fontsize=9)

    # Threat Badge
    ax.text(0.05, 0.77, "Trigger: Hybrid Consensus (Rule Violation + ML Anomaly)", color="#ef4444", fontsize=10, fontweight="bold")

    # Canonical Payload with Highlights
    ax.text(0.05, 0.68, "Canonical Request Inspection:", color="#f8fafc", fontsize=10, fontweight="bold")
    ax.text(0.05, 0.61, "post /rest/user/login  username=", color="#e2e8f0", fontfamily="monospace", fontsize=10)
    ax.text(0.35, 0.61, "admin' OR '1'='1", color="#ffffff", backgroundcolor="#dc2626", fontfamily="monospace", fontsize=10, fontweight="bold")
    ax.text(0.53, 0.61, "  &password=dummy", color="#e2e8f0", fontfamily="monospace", fontsize=10)

    # Contributing Tokens Section
    ax.text(0.05, 0.50, "Top Contributing Token Attributions (Linear Explainer):", color="#f8fafc", fontsize=10, fontweight="bold")
    tokens = [
        ("Token: ' OR '1'='1", "Weight: +0.8942", "High-confidence SQL tautology construct", "#ef4444"),
        ("Token: ' OR ", "Weight: +0.4120", "Boolean logic clause injection", "#f97316"),
        ("Token: admin'", "Weight: +0.2851", "Unescaped single-quote authentication bypass", "#eab308"),
    ]
    y = 0.43
    for t_title, w_val, desc, col in tokens:
        ax.text(0.08, y, f"• {t_title:<22}  ({w_val}) — {desc}", color=col, fontfamily="monospace", fontsize=9)
        y -= 0.06

    # Dense Lexical Features
    ax.text(0.05, 0.22, "Dense Lexical Threat Indicators:", color="#f8fafc", fontsize=10, fontweight="bold")
    ax.text(0.08, 0.16, "• SQL Keyword Count: 1 ('OR')\n• Quote/Comment Count: 4 (' )\n• Special Character Ratio: 0.21 (Threshold: 0.15)", color="#94a3b8", fontfamily="monospace", fontsize=9)

    # Matched Signature Rule
    ax.text(0.05, 0.06, "Matched Rule: SQLI-RULE-001 (OWASP A03:2021 — Classic SQL Injection Tautology)", color="#38bdf8", fontfamily="monospace", fontsize=9)

    ax.set_xticks([])
    ax.set_yticks([])
    for spine in ax.spines.values():
        spine.set_color("#334155")

    out = SCREENSHOTS_DIR / "explanation_drawer.png"
    plt.savefig(out, dpi=200, facecolor=fig.get_facecolor(), bbox_inches="tight")
    plt.close()
    print(f"[+] Created {out}")


def create_model_eval_mockup():
    fig = plt.figure(figsize=(12, 7), dpi=200, facecolor="#0f172a")
    ax = fig.add_subplot(111)
    ax.set_facecolor("#1e293b")

    ax.text(0.05, 0.92, "Model Evaluation & Baseline Benchmark Dashboard", color="#f8fafc", fontsize=13, fontweight="bold")
    ax.text(0.05, 0.86, "Active Model: Stage3_Robust_20261114_204029 (LogisticRegression_Augmented) | Calibrated Threshold: 0.940", color="#38bdf8", fontsize=9)

    # Comparison Table
    headers = "Corpus / Scenario          AI-WAF Hybrid      ModSecurity PL1    Serial Combo    Target (PRD 1.8)"
    divider = "―" * 90
    rows = [
        ("In-Distribution Test (N=2,526)  97.94% Recall      27.48% Recall      98.04%          >= 90.0%  (MET)", "#10b981"),
        ("Family B Zero-Day Evasions       90.32% Recall      24.15% Recall      90.43%          >= 75.0%  (MET)", "#10b981"),
        ("Neutral Independent Benchmark    83.60% Recall      32.40% Recall      83.60%          Neutral   (MET)", "#10b981"),
        ("Cross-Source CSIC 2010           20.29% Recall      15.15% Recall      22.10%          > 15.0%   (MET)", "#10b981"),
        ("Large Benign Traffic (N=3,000)   0.00% FPR (0.12%)  0.00% FPR (0.12%)  0.00% FPR       <= 1.0%   (MET)", "#10b981"),
        ("Inspection Latency (p95)         2.55 ms            4.80 ms            7.35 ms         <= 25.0ms (MET)", "#10b981"),
    ]

    ax.text(0.05, 0.74, headers, color="#f8fafc", fontfamily="monospace", fontsize=9, fontweight="bold")
    ax.text(0.05, 0.70, divider, color="#475569", fontfamily="monospace", fontsize=9)

    y = 0.64
    for row_text, color in rows:
        ax.text(0.05, y, row_text, color=color, fontfamily="monospace", fontsize=9)
        y -= 0.08

    # Bottom notes
    ax.text(0.05, 0.12, "Key Empirical Conclusion: Character n-gram tokenization provides +66.2% higher recall on novel Family B mutations.\nSerial combination of AI-WAF and ModSecurity delivers 90.43% composite protection on zero-day attacks with < 7.5ms total latency.", color="#94a3b8", fontsize=9)

    ax.set_xticks([])
    ax.set_yticks([])
    for spine in ax.spines.values():
        spine.set_color("#334155")

    out = SCREENSHOTS_DIR / "model_eval_page.png"
    plt.savefig(out, dpi=200, facecolor=fig.get_facecolor(), bbox_inches="tight")
    plt.close()
    print(f"[+] Created {out}")


if __name__ == "__main__":
    create_dashboard_mockup()
    create_explanation_drawer_mockup()
    create_model_eval_mockup()
