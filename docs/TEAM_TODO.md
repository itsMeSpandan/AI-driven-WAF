# Team Handover & Submission Checklist (`docs/TEAM_TODO.md`)

**Target Milestone**: Final Course Project Submission & Viva Voce (2026)  
**Project**: AI-Driven Web Application Firewall & Real-Time Analytics Dashboard  
**Release Tag**: `v1.0` (Tagged locally)  
**Primary Deliverables**: `docs/FINAL_REPORT.docx`, `docs/SLIDES.md`, `docs/DEMO.md`, `eval/results.md`

This document provides a comprehensive, actionable checklist of the manual steps required of the 3-person student engineering team prior to project submission and evaluation.

---

## 1. Final Report Finalisation (`docs/FINAL_REPORT.docx` / `.md`)
- [ ] **Author Metadata**: Open `docs/FINAL_REPORT.docx` (or `docs/FINAL_REPORT.md`) and replace placeholder author information (Section 1) with your actual names, student roll numbers, department name, institution name, and academic supervisor name.
- [ ] **Regenerate DOCX**: If you edited `docs/FINAL_REPORT.md`, regenerate the Word document with:
  ```bash
  python docs/export_docx.py
  ```
- [ ] **Visual Proofreading**: Verify that all 4 tables and 2 figures (`Confusion Matrices` and `Latency vs Concurrency`) render cleanly with appropriate margins and captions in Microsoft Word or LibreOffice.
- [ ] **Optional PDF Export**: If the course guidelines require PDF format, export using Pandoc:
  ```bash
  pandoc docs/FINAL_REPORT.md -o docs/FINAL_REPORT.pdf --pdf-engine=xelatex
  ```
  *(Or export directly from Microsoft Word: File $\rightarrow$ Save As $\rightarrow$ PDF).*

---

## 2. Slide Deck Construction (`docs/SLIDES.md`)
- [ ] **Import into PowerPoint / Google Slides**: Copy the 12 slide outlines from `docs/SLIDES.md` into your university's presentation template.
- [ ] **Paste Visual Figures**:
  - Slide 1 & 4: Insert `docs/diagrams/system_architecture.png`.
  - Slide 6: Insert `docs/diagrams/request_lifecycle.png`.
  - Slide 8: Insert `eval/figures/confusion_matrices.png`.
  - Slide 10: Insert `eval/figures/latency_concurrency.png`.
  - Slide 11: Insert `docs/diagrams/model_lifecycle.png`.
- [ ] **Speaker Division**: Divide the 12 slides evenly across the 3 team members:
  - **Speaker 1 (Slides 1–4, ~1.5 min)**: Executive summary, problem statement, engineering goals G1–G7, system architecture.
  - **Speaker 2 (Slides 5–8, ~1.5 min)**: Normalisation, sub-word n-grams, linear Shapley explainability, evaluation parity & detection benchmark.
  - **Speaker 3 (Slides 9–12, ~2.0 min)**: Zero-day evasion robustness, latency/concurrency scaling, safe analyst loop, conclusions & demo transition.

---

## 3. Demo Video Recording & Rehearsal (`docs/DEMO.md`)
- [ ] **Install Screen Recorder**: Install OBS Studio, Loom, or Windows Game Bar (`Win + G`) configured for 1080p 60fps desktop capture with clear microphone audio.
- [ ] **Run Pre-Flight Reset**:
  ```bash
  make up
  make demo-reset
  ```
- [ ] **Perform Timed Dry-Runs**: Follow the exact script in `docs/DEMO.md`:
  - Beat 1 (0:00–1:00): Pass-through benign search (`apple juice`).
  - Beat 2 (1:00–2:00): Textbook SQL injection (`admin' OR '1'='1--`) blocked by rule layer.
  - Beat 3 (2:00–3:00): Obfuscated SQL injection (`select and 0x61=0x61`) caught by ML detector with explanation drawer.
  - Beat 4 (3:00–4:00): Monitor mode vs. Block mode toggle live.
  - Beat 5 (4:00–4:30): Model & Eval tab (`http://localhost:3000/models`) showing head-to-head ModSecurity comparison.
  - Beat 6 (4:30–5:00): Wrap-up.
- [ ] **Target Video Duration**: Exactly **3 to 5 minutes**. Ensure background noise is minimized and terminal fonts are large (16pt+).
- [ ] **Upload Video**: Export as MP4 (`demo_video_v1.0.mp4`) and upload to Google Drive / YouTube (unlisted) per course submission instructions.

---

## 4. Viva Voce & Technical Defense Preparation

Prepare concise, confident answers to these expected panel questions:

### Q1: "Why did you use Logistic Regression instead of Deep Learning (e.g. BERT or an LSTM)?"
> **Answer**: *"For three critical engineering reasons:
> 1. **Inference Latency SLA**: Under our PRD G4 requirement, proxy overhead must not exceed 25 ms. Our Logistic Regression scores requests in 1.41 ms. A BERT transformer would require 80–200 ms without GPU acceleration, stalling proxy throughput.
> 2. **Sub-Millisecond Explainability**: Because feature sparsity in our 20,000 sub-word space exceeds 99.8%, linear feature attribution $w_i x_i$ mathematically converges to exact Shapley values ($w_i(x_i - E[X_i])$) in < 1.0 ms. Deep models require perturbation explainers (LIME/SHAP) taking > 1,200 ms.
> 3. **Memory & Deployment Footprint**: The entire model is 2.00 MB, fitting comfortably into constrained containers without requiring GPU runtimes."*

### Q2: "Why do sub-word character n-grams outperform word tokenizers on evasive attacks?"
> **Answer**: *"Word tokenizers look for complete space-separated words like `SELECT` or `UNION`. Attackers easily defeat them using inline comments (`SEL/**/ECT`), concatenation (`CONCAT('te','xt')`), or double encoding (`%2527`). Our character 3-to-5 n-grams break down normalized tokens into overlapping character slices. Even if `UNION` is mutated, sub-grams like `uni`, `nio`, and `ion` still match strongly weighted features, achieving 90.32% recall on zero-day mutations."*

### Q3: "What is the difference between Family A and Family B mutations?"
> **Answer**: *"To prevent data leakage and guarantee an honest zero-day test, we strictly separated our mutation families before training:
> - **Family A (Seen for Training, 16,824 samples)**: Case swapping, single URL encoding, whitespace manipulation, inline SQL comments, and operator swaps.
> - **Family B (Strictly Held-Out for Testing, 857 samples)**: Hex literal encodings (`0x...`), double URL encoding (`%25...`), dynamic JavaScript character codes (`String.fromCharCode`), and obscure HTML5 event tags. The model never encountered Family B syntax during training."*

### Q4: "How did you ensure fairness in your ModSecurity CRS benchmark?"
> **Answer**: *"We enforced strict Docker container hardware parity: both our WAF Gateway and the official ModSecurity Apache container (`owasp/modsecurity-crs:4.8.0-apache`) were pinned to exactly 1.0 CPU core and 512MB RAM. Both engines inspected raw HTTP wire requests (not pre-canonicalized text) replayed through identical network proxies to upstream targets, and we computed Wilson 95% Confidence Intervals for all statistics."*

### Q5: "What happens if the SQLite database locks or crashes during heavy traffic?"
> **Answer**: *"Our proxy completely decouples inspection latency from database persistence. The gateway inspects the request in memory and returns the HTTP decision immediately, pushing the event payload into an asynchronous in-memory queue (`asyncio.Queue`). A background worker drains the queue to the database. If the database locks or fails, the proxy logs a warning and continues processing live traffic without blocking user requests."*

### Q6: "Why did detection drop on the Spanish CSIC 2010 corpus (20.29% recall)?"
> **Answer**: *"CSIC 2010 represents an extreme out-of-distribution domain shift: it consists of Spanish eCommerce parameter tampering (e.g. modifying prices or quantities on `/tienda1/`) rather than syntactic injection attacks. Because the vocabulary of the routes differed completely from our training set, pure ML scored 1.18%. However, our hybrid rule layer caught 20.29%, highlighting why defense-in-depth pairing rules with ML is essential."*

---

## 5. Final Submission Archive Packaging
- [ ] **Verify Git Clean State**:
  ```bash
  git status
  pytest -v
  ```
- [ ] **Verify Local Tag**:
  ```bash
  git tag -l -n
  ```
  *(Expected: `v1.0 Release v1.0: AI-Driven WAF with Analytics Dashboard`)*.
- [ ] **Create Submission Zip**: If a zip file is required by your university portal:
  ```bash
  git archive --format=zip --output=ai_waf_v1.0_submission.zip v1.0
  ```
  *(This creates a clean, lightweight zip containing only tracked files and the 2.00 MB model, free of `.pytest_cache`, `node_modules`, or database files).*
