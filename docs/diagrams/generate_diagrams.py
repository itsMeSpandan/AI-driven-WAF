"""
Generates publication-quality architecture figures in docs/diagrams/:
  1. system_architecture.png
  2. request_lifecycle.png
  3. model_lifecycle.png
"""

from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as patches

DIAGRAMS_DIR = Path(__file__).resolve().parent
DIAGRAMS_DIR.mkdir(parents=True, exist_ok=True)

plt.rcParams.update({
    "font.family": "sans-serif",
    "font.size": 10,
})

def create_system_architecture():
    fig, ax = plt.subplots(figsize=(14, 8), dpi=250, facecolor="#0f172a")
    ax.set_facecolor("#0f172a")

    # Title
    ax.text(0.5, 0.95, "AI-Driven WAF & Real-Time Analytics Dashboard — System Architecture", 
            color="#f8fafc", fontsize=15, fontweight="bold", ha="center")

    # Components boxes
    boxes = [
        # Client
        (0.04, 0.45, 0.12, 0.25, "Client / Attacker\n\nHTTP Requests\n(Curl / Browser)", "#334155", "#94a3b8"),
        # Gateway
        (0.22, 0.20, 0.32, 0.65, "WAF Reverse-Proxy Gateway (:8080)\n\n"
                                 "• Iterative Multi-pass Normalizer\n"
                                 "• In-Memory Sliding-Window Rate Limiter\n"
                                 "• Signature Rule Layer (29 ReDoS-immune regexes)\n"
                                 "• Logistic Regression Detector (TF-IDF + Lexical)\n"
                                 "• Cached Linear Token Attribution Explainer\n"
                                 "• Async Event Logging Queue (Non-blocking)", "#1e293b", "#38bdf8"),
        # Protected Upstream App
        (0.62, 0.60, 0.32, 0.25, "Protected Application (:3000 internal)\n\n"
                                 "• OWASP Juice Shop / DVWA\n"
                                 "• Isolated in internal docker network\n"
                                 "• Zero published host ports", "#1e293b", "#10b981"),
        # Database Store
        (0.62, 0.20, 0.32, 0.32, "Database Store (SQLite / PostgreSQL)\n\n"
                                 "• Events table (Incident logs & explanations)\n"
                                 "• Feedback table (Analyst corrections)\n"
                                 "• Config & ConfigAudit tables\n"
                                 "• Schema enforced via SQLAlchemy ORM", "#1e293b", "#f59e0b"),
        # Dashboard API & UI
        (0.22, 0.02, 0.72, 0.14, "SecOps Analytics & Management Plane\n\n"
                                 "Dashboard API (:8000 FastAPI, SSE, HS256 JWT)   ◄──►   Next.js 14 Dashboard UI (:3000 Recharts, Tailwind)", "#1e293b", "#a855f7"),
    ]

    for x, y, w, h, text, facecol, edgecol in boxes:
        rect = patches.FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.03",
                                      facecolor=facecol, edgecolor=edgecol, linewidth=2)
        ax.add_patch(rect)
        ax.text(x + w/2, y + h/2, text, color="#f8fafc", fontsize=9, ha="center", va="center", fontweight="medium")

    # Arrows
    # Client -> Gateway
    ax.annotate("", xy=(0.22, 0.57), xytext=(0.16, 0.57),
                arrowprops=dict(arrowstyle="->", color="#38bdf8", lw=2.5))
    ax.text(0.19, 0.60, "HTTP", color="#38bdf8", fontsize=9, ha="center", fontweight="bold")

    # Gateway -> Upstream (Allowed)
    ax.annotate("", xy=(0.62, 0.72), xytext=(0.54, 0.72),
                arrowprops=dict(arrowstyle="->", color="#10b981", lw=2.5))
    ax.text(0.58, 0.75, "200 Forward", color="#10b981", fontsize=9, ha="center", fontweight="bold")

    # Gateway -> DB (Async Log)
    ax.annotate("", xy=(0.62, 0.36), xytext=(0.54, 0.36),
                arrowprops=dict(arrowstyle="->", color="#f59e0b", lw=2.5, linestyle="--"))
    ax.text(0.58, 0.39, "Async Log", color="#f59e0b", fontsize=9, ha="center", fontweight="bold")

    # DB -> Dashboard Plane
    ax.annotate("", xy=(0.78, 0.16), xytext=(0.78, 0.20),
                arrowprops=dict(arrowstyle="<->", color="#a855f7", lw=2))

    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    out_file = DIAGRAMS_DIR / "system_architecture.png"
    plt.savefig(out_file, dpi=250, facecolor=fig.get_facecolor(), bbox_inches="tight")
    plt.close()
    print(f"[+] Saved {out_file}")


def create_request_lifecycle():
    fig, ax = plt.subplots(figsize=(13, 7), dpi=250, facecolor="#0f172a")
    ax.set_facecolor("#0f172a")

    ax.text(0.5, 0.95, "Request Lifecycle & Hybrid Inspection Pipeline", 
            color="#f8fafc", fontsize=14, fontweight="bold", ha="center")

    steps = [
        ("1. Ingestion & Anti-Spoofing", "Client IP resolved via Trusted Proxies;\nSliding-window rate checked (< 15us)", 0.05),
        ("2. Request Normalisation", "Multi-pass unquote, NFKC Unicode, comment\nstripping, canonical text generated", 0.23),
        ("3. Signature Rule Layer", "29 OWASP-style regexes (< 0.1ms);\nFast denylist check for textbook SQLi/XSS", 0.41),
        ("4. ML Threat Scoring", "Char n-grams (3,5) + 8 dense lexical features;\nScore vs calibrated threshold (tau=0.94)", 0.59),
        ("5. Decision & Explainer", "Consensus verdict (Block/Flag/Allow);\nLinear token attribution mapped to spans", 0.77),
    ]

    for title, desc, x in steps:
        rect = patches.FancyBboxPatch((x, 0.40), 0.16, 0.42, boxstyle="round,pad=0.02,rounding_size=0.02",
                                      facecolor="#1e293b", edgecolor="#38bdf8", linewidth=1.8)
        ax.add_patch(rect)
        ax.text(x + 0.08, 0.72, title, color="#38bdf8", fontsize=9, fontweight="bold", ha="center")
        ax.text(x + 0.08, 0.54, desc, color="#cbd5e1", fontsize=8, ha="center", va="center")

    # Connect arrows between steps
    for i in range(len(steps) - 1):
        x1 = steps[i][2] + 0.16
        x2 = steps[i+1][2]
        ax.annotate("", xy=(x2, 0.61), xytext=(x1, 0.61),
                    arrowprops=dict(arrowstyle="->", color="#94a3b8", lw=2))

    # Outcomes Box
    # Block Outcome
    rect_block = patches.FancyBboxPatch((0.55, 0.10), 0.38, 0.20, boxstyle="round,pad=0.02,rounding_size=0.02",
                                         facecolor="#1e293b", edgecolor="#ef4444", linewidth=2)
    ax.add_patch(rect_block)
    ax.text(0.74, 0.24, "VERDICT: BLOCK (HTTP 403)", color="#ef4444", fontsize=11, fontweight="bold", ha="center")
    ax.text(0.74, 0.15, "• Incident logged with Request ID\n• Contributing token spans highlighted in SecOps drawer\n• Client IP incremented in rate burst penalty counter", color="#cbd5e1", fontsize=8, ha="center")

    # Allow Outcome
    rect_allow = patches.FancyBboxPatch((0.07, 0.10), 0.38, 0.20, boxstyle="round,pad=0.02,rounding_size=0.02",
                                         facecolor="#1e293b", edgecolor="#10b981", linewidth=2)
    ax.add_patch(rect_allow)
    ax.text(0.26, 0.24, "VERDICT: ALLOW (HTTP 200)", color="#10b981", fontsize=11, fontweight="bold", ha="center")
    ax.text(0.26, 0.15, "• Hop-by-hop headers stripped\n• X-Forwarded-For & X-WAF-Request-ID attached\n• Streamed asynchronously to protected upstream app", color="#cbd5e1", fontsize=8, ha="center")

    # Decision branches
    ax.annotate("", xy=(0.74, 0.30), xytext=(0.85, 0.40),
                arrowprops=dict(arrowstyle="->", color="#ef4444", lw=2, linestyle="--"))
    ax.annotate("", xy=(0.26, 0.30), xytext=(0.85, 0.40),
                arrowprops=dict(arrowstyle="->", color="#10b981", lw=2, linestyle="--"))

    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    out_file = DIAGRAMS_DIR / "request_lifecycle.png"
    plt.savefig(out_file, dpi=250, facecolor=fig.get_facecolor(), bbox_inches="tight")
    plt.close()
    print(f"[+] Saved {out_file}")


def create_model_lifecycle():
    fig, ax = plt.subplots(figsize=(13, 7), dpi=250, facecolor="#0f172a")
    ax.set_facecolor("#0f172a")

    ax.text(0.5, 0.95, "Continuous ML Model Lifecycle & Safe Feedback Promotion Loop", 
            color="#f8fafc", fontsize=14, fontweight="bold", ha="center")

    phases = [
        (0.05, 0.55, "1. Ingestion & Augmentation", "• Curated SQLi / XSS corpora\n• Split before augmentation\n• Family A mutations for training\n• Family B reserved for zero-day eval", "#38bdf8"),
        (0.38, 0.55, "2. Feature Pipeline & Model Training", "• Char n-grams (3,5) up to 20k vocab\n• 8 dense lexical markers\n• LogisticRegression fit with L2\n• Calibrated threshold tau=0.940", "#38bdf8"),
        (0.71, 0.55, "3. Active Gateway Serving", "• Sub-millisecond inference (< 2.5ms)\n• Non-blocking threadpool execution\n• Sub-word token attribution caching\n• Fail-open / closed safety policy", "#10b981"),
        (0.71, 0.10, "4. SecOps Feedback Ingestion", "• Analyst flags FP or TP in drawer\n• Anti-poisoning defense: high-severity\n  signature conflicts rejected\n• Deduplicated by canonical text", "#f59e0b"),
        (0.38, 0.10, "5. Automated Safety Gates", "• Candidate model retrained\n• Gate 1: FPR <= 2.5%\n• Gate 2: Family B recall drop <= 2.0%\n• Gate 3: OOD CSIC drop <= 2.0%\n• Gate 4: p95 latency <= 10.0 ms", "#ef4444"),
        (0.05, 0.10, "6. Atomic Promotion & Rollback", "• Candidate promoted to active\n• Previous active backed up\n• Atomic symlink / file swap\n• Instant one-command rollback", "#a855f7"),
    ]

    for x, y, title, desc, col in phases:
        rect = patches.FancyBboxPatch((x, y), 0.24, 0.32, boxstyle="round,pad=0.02,rounding_size=0.02",
                                      facecolor="#1e293b", edgecolor=col, linewidth=2)
        ax.add_patch(rect)
        ax.text(x + 0.12, y + 0.26, title, color=col, fontsize=9, fontweight="bold", ha="center")
        ax.text(x + 0.12, y + 0.13, desc, color="#cbd5e1", fontsize=8, ha="center", va="center")

    # Connect forward pipeline
    ax.annotate("", xy=(0.38, 0.71), xytext=(0.29, 0.71), arrowprops=dict(arrowstyle="->", color="#38bdf8", lw=2))
    ax.annotate("", xy=(0.71, 0.71), xytext=(0.62, 0.71), arrowprops=dict(arrowstyle="->", color="#38bdf8", lw=2))

    # Connect feedback loop (Downward and Leftward)
    ax.annotate("", xy=(0.83, 0.42), xytext=(0.83, 0.55), arrowprops=dict(arrowstyle="->", color="#f59e0b", lw=2, linestyle="--"))
    ax.annotate("", xy=(0.62, 0.26), xytext=(0.71, 0.26), arrowprops=dict(arrowstyle="->", color="#f59e0b", lw=2, linestyle="--"))
    ax.annotate("", xy=(0.29, 0.26), xytext=(0.38, 0.26), arrowprops=dict(arrowstyle="->", color="#ef4444", lw=2, linestyle="--"))
    ax.annotate("", xy=(0.17, 0.55), xytext=(0.17, 0.42), arrowprops=dict(arrowstyle="->", color="#a855f7", lw=2, linestyle="--"))

    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    out_file = DIAGRAMS_DIR / "model_lifecycle.png"
    plt.savefig(out_file, dpi=250, facecolor=fig.get_facecolor(), bbox_inches="tight")
    plt.close()
    print(f"[+] Saved {out_file}")

if __name__ == "__main__":
    create_system_architecture()
    create_request_lifecycle()
    create_model_lifecycle()
