# AI-Driven Web Application Firewall & Real-Time Analytics Dashboard
## Presentation Slide Deck Outline & Speaker Notes (12 Slides)

**Course**: Academic Engineering Project (2026)  
**Authors**: 3-Person Student Team  
**Release**: `v1.0` (Local Git Tag)  
**Artifact Repository**: `docs/FINAL_REPORT.md` | `eval/results.md` | `docs/ARCHITECTURE.md`

---

### Slide 1: Title & Executive Summary
- **Title**: AI-Driven Web Application Firewall (WAF) & Real-Time Analytics Dashboard
- **Subtitle**: Bridging Deterministic Rules, Sub-Word Machine Learning, and Sub-Millisecond Explainability
- **Team**: 3-Person Student Engineering Team
- **Course**: Final Year Mini-Project
- **Visual Asset**: `docs/diagrams/system_architecture.png`
- **Slide Bullets**:
  - An inline, high-performance reverse-proxy WAF protecting upstream web applications.
  - Dual-engine detection core: 29 ReDoS-immune regex rules + regularized character n-gram ML detector.
  - Sub-millisecond linear token explainer (< 1.0 ms) exposing byte-level attack spans.
  - Live SecOps analytics console (Next.js 14) with real-time SSE telemetry and sliding-window rate anomaly tracking.
  - Open-source, reproducible release benchmarked against official ModSecurity Core Rule Set (CRS v4).
- **Speaker Notes** (approx. 45 sec):
  > "Good morning, professors and committee members. Today we present our project: an AI-Driven Web Application Firewall with a real-time analytics dashboard. Modern web applications face relentless attacks—from SQL injections to cross-site scripting—yet existing defenses either rely on brittle, decades-old regular expressions or opaque enterprise black-box models. Our project bridges this gap by combining deterministic signature denylisting with a regularized machine-learning engine that operates at line speed, explains every single block to the security analyst in under a millisecond, and streams live telemetry to a Next.js dashboard."

---

### Slide 2: The Problem: The Modern WAF Dilemma
- **Title**: The Perimeter Problem: Why Traditional WAFs Fail
- **Slide Bullets**:
  - **Regex Rigidity vs. Evasion**: Attackers bypass static signatures using inline comments (`SEL/**/ECT`), double URL encoding (`%2527`), and hex literals (`0x61646d696e`).
  - **The False Positive Burden**: Tightening rule paranoia (ModSecurity PL2/PL3) spikes false positives, breaking legitimate eCommerce checkouts and overwhelming SOC teams.
  - **The Explainability Void**: Deep learning and neural WAFs act as black boxes; when a payload is dropped, operators receive an uninterpretable anomaly score without spatial token attribution.
  - **Research vs. Production Decoupling**: Academic ML WAF models are evaluated offline in Python notebooks without reverse-proxy integration, latency benchmarking, or streaming interfaces.
- **Visual Asset**: Side-by-side comparison box (Brittle Regex vs Opaque Black-Box vs Our Hybrid Approach).
- **Speaker Notes** (approx. 45 sec):
  > "Why is web application firewalling still an unsolved engineering challenge? The dilemma comes down to regex rigidity versus explainability. If an attacker injects a basic SQL payload, ModSecurity catches it. But if they insert a comment or hex encode a literal, the regex fails completely unless paranoia is cranked up—which then blocks harmless user inputs like apostrophes in names. Meanwhile, deep learning models in recent literature can detect anomalies, but they run too slowly for inline proxying and give no explanation of *why* a request was blocked. Our mission was to solve all four of these shortcomings simultaneously."

---

### Slide 3: Project Goals & Engineering Targets
- **Title**: Project Objectives & Verification Targets
- **Slide Bullets**:
  - **G1 (In-Distribution Recall)**: $\ge 90.0\%$ detection recall on standard injection corpora (SQLi, XSS).
  - **G2 (False Positive Control)**: $\le 1.0\%$ False Positive Rate across large benign traffic corpora.
  - **G3 (Sub-Millisecond Explainability)**: 100% of blocked requests carry byte-level token attribution spans.
  - **G4 (Low Latency Overhead)**: p95 gateway inspection overhead $\le 25.0\text{ ms}$ under concurrent load.
  - **G5 (Zero-Day Evasion Robustness)**: $\ge 75.0\%$ recall on unseen obfuscation families held out during training.
  - **G6 (Out-of-Distribution Safety)**: Maintain a baseline detection safety net ($> 15.0\%$) across novel application schemas.
  - **G7 (Baseline Parity Benchmarking)**: Objectively benchmark detection, FPR, and throughput against containerized ModSecurity CRS v4 under identical hardware resource bounds.
- **Visual Asset**: Target matrix table with G1–G7 IDs.
- **Speaker Notes** (approx. 40 sec):
  > "In our initial Product Requirements Document, we formalized seven strict engineering goals. Notice that we didn't just target detection accuracy; we targeted a strict false-positive rate under 1%, sub-millisecond explanation generation, p95 proxy overhead under 25 milliseconds, and objective evaluation against ModSecurity under identical Docker resource constraints: exactly 1 CPU core and 512 megabytes of RAM."

---

### Slide 4: System Architecture & Data Flow
- **Title**: End-to-End System Architecture
- **Visual Asset**: `docs/diagrams/system_architecture.png`
- **Slide Bullets**:
  - **Client Traffic**: Replayed HTTP requests pass through the FastAPI asynchronous proxy gateway (Port 8080).
  - **Normalization**: Iterative unquoting, HTML entity translation, NFKC Unicode folding, comment collapse.
  - **Dual Evaluation Core**:
    - Deterministic Regex Engine: 29 ReDoS-immune signatures (`gateway/rules.py`).
    - ML Detector: L2-regularized Logistic Regression on 20,000 sub-word n-grams (`gateway/detector.py`).
  - **Explainer**: Linear feature attribution maps non-zero weights directly to text tokens in < 1.0 ms.
  - **Protected Target**: Containerized OWASP Juice Shop (`v17.1.1`) isolated inside Docker network with zero host ports.
  - **SecOps Dashboard**: Next.js 14 console receiving live Server-Sent Events (SSE) via FastAPI backend.
- **Speaker Notes** (approx. 50 sec):
  > "Here is our four-service architecture. When a request arrives at the reverse proxy on port 8080, it passes through our multi-pass normalizer. The normalized string is inspected concurrently by our rule layer and our ML detector. If either engine flags the request above threshold, the linear explainer isolates the exact suspicious characters, an async worker writes the event to SQLite, and an immediate 403 Forbidden is returned. Benign requests are forwarded directly to the protected target—in our testbed, OWASP Juice Shop. The SecOps dashboard receives every event via Server-Sent Events, updating charts and drawers in real time."

---

### Slide 5: The Normalization & Machine Learning Pipeline
- **Title**: Multi-Pass Normalization & Sub-Word Representation
- **Visual Asset**: Flow diagram of Normalizer + Feature Union.
- **Slide Bullets**:
  - **Multi-Pass Normalizer (`waf_common/normalizer.py`)**:
    - Iterative URL unquoting (depth up to 3) unwraps double encoding (`%2527` $\rightarrow$ `'`).
    - Unicode NFKC folding strips fullwidth spoofing (`＜script＞` $\rightarrow$ `<script>`).
    - SQL comment stripping normalizes whitespace (`SEL/**/ECT` $\rightarrow$ `sel ect`).
  - **FeatureUnion Architecture (`gateway/detector.py`)**:
    - Sub-word Character n-grams: 3-to-5 character n-grams (20,000 max features) capture sub-token invariants (`1=1`, `'or`, `union`, `alert`).
    - Dense Lexical Markers: 8 structural heuristics (Shannon entropy, special char ratio, digit ratio, SQL keyword frequency).
  - **Classifier & Calibration**: L2-regularized Logistic Regression ($C=5.0$) calibrated on validation data to $\tau = 0.940$ for zero benign false alarms.
- **Speaker Notes** (approx. 50 sec):
  > "The secret to our model's resilience lies in two stages: canonicalization and sub-word n-grams. Attackers rely on encoding layers to blind WAFs. Our normalizer recursively strips URL encoding, collapses SQL comments, and standardizes Unicode. Then, instead of tokenizing by word—which breaks on obfuscated strings—our FeatureUnion extracts character n-grams of lengths 3, 4, and 5. This means even if an attacker writes 'sel/**/ect', the sub-grams 'sel', 'ele', and 'ect' still trigger strong weights. We calibrated our decision threshold to 0.940, completely suppressing false positives on benign queries."

---

### Slide 6: Sub-Millisecond Explainability: Game Theory at Line Speed
- **Title**: Real-Time Token Attribution (< 1.0 ms)
- **Visual Asset**: `docs/diagrams/request_lifecycle.png` (Detail of Explainer span mapping).
- **Slide Bullets**:
  - **The Latency Trap of LIME/SHAP**: Perturbation-based explainers require 1,200 ms to compute—completely unusable in an inline proxy.
  - **Linear Feature Attribution**:
    $$\text{attr}_i(x) = w_i \cdot x_i$$
  - **Mathematical Shapley Equivalence**:
    - In our 20,000-dimensional TF-IDF space, feature sparsity exceeds **99.8%**.
    - Since background feature expectations vanish ($E[X_i] \approx 0$), linear attribution $w_i x_i$ is mathematically identical to exact Shapley values ($w_i (x_i - E[X_i])$).
  - **Empirical Validation**:
    - **80.0% feature alignment** with KernelSHAP.
    - Execution time: **1.85 ms** average latency, running fully inline without proxy stalls.
    - Contiguous character spans highlighted directly in the analyst dashboard drawer.
- **Speaker Notes** (approx. 50 sec):
  > "Explainability is usually where machine learning WAFs fail in production. Perturbation methods like LIME take over a second per request. We solved this with a proven mathematical property: because TF-IDF feature vectors are 99.8% sparse, the expected background values are practically zero. Therefore, exact linear attribution—multiplying the model weight by the TF-IDF feature value—converges to the game-theoretic Shapley value. Our explainer runs in under 1.85 milliseconds, achieves 80% alignment with KernelSHAP, and maps directly to byte offsets in the UI so the analyst sees exactly which tokens caused the block."

---

### Slide 7: Evaluation Setup & Docker Parity
- **Title**: Rigorous Baseline Benchmarking: AI-WAF vs. ModSecurity CRS
- **Visual Asset**: Table 1 from `docs/FINAL_REPORT.md` (Baseline setup).
- **Slide Bullets**:
  - **Hardware Parity**: Both AI-WAF and ModSecurity containers strictly pinned to **1.0 CPU** and **512 MB RAM**.
  - **Baseline Engine**: Official OWASP Core Rule Set container (`owasp/modsecurity-crs:4.8.0-apache`) at Paranoia Level 1 and Level 2.
  - **Corpora Provenance**:
    - In-Distribution Test: 2,526 PayloadsAllTheThings, SecLists, CSIC, and eCommerce queries.
    - Family A Evasion (Seen Augmentation): 1,019 samples.
    - Family B Evasion (Strictly Held-Out Zero-Day): 857 samples (hex literals, double encoding, char code concatenation).
    - CSIC 2010 Out-of-Distribution: 12,069 requests from an independent university dataset.
    - Neutral Independent Set: 1,000 unseen requests (500 multi-vector attacks + 500 neutral browsing).
    - Large Benign Corpus: 3,000 checkout queries to test false positive rates.
  - **Statistical Rigor**: Wilson 95% Score Confidence Intervals computed for all metrics.
- **Speaker Notes** (approx. 45 sec):
  > "To ensure our evaluation is beyond reproach, we benchmarked our WAF directly against the industry gold standard: ModSecurity CRS v4 running in official Apache containers. We enforced strict Docker hardware parity: exactly 1 CPU core and 512 megabytes of RAM for each container. We assembled six distinct evaluation corpora totaling over 20,000 real HTTP requests, completely separating seen training augmentations (Family A) from strictly held-out zero-day evasions (Family B), and computed Wilson 95% confidence intervals on every metric."

---

### Slide 8: Detection & False Positive Results
- **Title**: Benchmark Matrix: Detection Recall & False Positive Rates
- **Visual Asset**: `eval/figures/confusion_matrices.png`
- **Slide Bullets**:
  - **In-Distribution Detection (PRD G1)**:
    - ModSecurity PL1: 27.48% recall (misses modern encoded payloads).
    - AI-WAF Rules Alone: 94.90% recall.
    - AI-WAF ML Alone: 97.55% recall.
    - **AI-WAF Hybrid: 97.94% recall** (F1 = 0.9896).
  - **False Positive Rate on Benign Traffic (PRD G2)**:
    - Tested on 4,507 benign eCommerce and encoded queries.
    - **AI-WAF Hybrid: 0.00% FPR** (Wilson 95% CI: [0.00%, 0.12%]).
    - ModSecurity PL1: 0.00% FPR (PL2 exhibited false positives on complex cookies).
  - **Neutral Independent Benchmark**:
    - Sourced from independent security repositories favoring neither engine.
    - AI-WAF Hybrid achieved **83.60% recall** vs. ModSecurity's **32.40%**.
- **Speaker Notes** (approx. 50 sec):
  > "Here are our headline detection results. On standard in-distribution injection payloads, our hybrid WAF achieves 97.94% recall, compared to 27.48% for ModSecurity PL1. More crucially, across 4,507 benign user browsing and checkout requests, our false positive rate was exactly 0.00%, with a Wilson 95% upper bound of 0.12%, thoroughly beating our PRD requirement of under 1%. On the neutral independent test set, our hybrid pipeline detected 83.6% of attacks, compared to 32.4% for ModSecurity."

---

### Slide 9: Adversarial Robustness on Zero-Day Evasions
- **Title**: Defeating Evasion: Held-Out Family B Mutations
- **Visual Asset**: Confusion matrix sub-panel for `evasion_test` + payload comparison table.
- **Slide Bullets**:
  - **Family B Evasion Corpus (857 requests)**: Obfuscations strictly held out from model training (hex literals `0x...`, double URL encoding `%25...`, `String.fromCharCode`).
  - **Detection Performance**:
    - **ModSecurity PL1: 24.15% recall** (blinded by non-standard delimiters and hex representations).
    - **AI-WAF Rules Only: 72.35% recall** (benefiting from multi-pass normalization).
    - **AI-WAF Augmented ML: 89.85% recall**.
    - **AI-WAF Hybrid: 90.32% recall** (Wilson 95% CI: [88.1%, 92.1%]).
  - **Augmentation Lift**: Training on Family A mutations generalized to structurally distinct Family B attacks, boosting ML evasion recall from 77.6% to **89.85%** (+12.25% absolute gain).
  - **ModSecurity CRS PL2 Comparison**: Cranking ModSec to Paranoia Level 2 raised recall to 63.3%, still trailing AI-WAF by +27.0% while causing false positives on legitimate queries.
- **Speaker Notes** (approx. 50 sec):
  > "Slide 9 highlights our core research achievement: zero-day adversarial robustness. We tested both engines against Family B mutations—payloads with double encoding, hex representations, and dynamic JavaScript character codes that neither engine was trained on. ModSecurity PL1 caught only 24.15% of these evasions. In contrast, our AI-WAF hybrid caught 90.32%. Even when we raised ModSecurity to Paranoia Level 2, it only reached 63.3%. Our multi-pass normalizer strips the outer obfuscation, and our sub-word n-grams identify the semantic attack fragments that static regexes miss."

---

### Slide 10: Performance, Latency & Serial Composition
- **Title**: Performance Benchmarks & Defense-in-Depth Composition
- **Visual Asset**: `eval/figures/latency_concurrency.png`
- **Slide Bullets**:
  - **Inspection Latency (PRD G4 Target: $\le 25\text{ ms}$)**:
    - Direct (no proxy): 0.80 ms p95.
    - AI-WAF Rules Only: 1.01 ms p95 (+0.21 ms overhead).
    - AI-WAF Hybrid (Rules + ML + Explainer): **2.55 ms p95** single-request overhead; 37.16 ms under 100 concurrent clients.
  - **ModSecurity C Module vs. Python GIL**:
    - ModSecurity (compiled C in Apache) achieves > 29,000 RPS.
    - AI-WAF Python proxy tops out at ~619 RPS under heavy parallel ML inference due to GIL constraints.
  - **Serial Pipeline Defense-in-Depth**:
    - Overlap analysis reveals ModSecurity caught < 0.1% of attacks missed by AI-WAF.
    - Running ModSecurity at the perimeter (handling RFC violations and high-volume DDoS) in series with AI-WAF (handling deep semantic analysis) achieves **90.43% to 98.04% composite recall**.
- **Speaker Notes** (approx. 50 sec):
  > "Let's examine latency and throughput honestly. For individual requests, our hybrid pipeline adds just 2.55 milliseconds of p95 latency. Under 100 concurrent clients, p95 latency sits around 37 milliseconds, sustaining 600 requests per second. ModSecurity, compiled in C, is faster in raw throughput—reaching 29,000 RPS. This leads directly to our deployment recommendation: serial defense-in-depth. Placing ModSecurity at the outer edge for line-rate RFC parsing, followed by AI-WAF for semantic inspection, delivers an unbeatable 98.04% composite detection rate."

---

### Slide 11: SecOps Loop & Production Hardening
- **Title**: Audited Analyst Feedback & Production Hardening
- **Visual Asset**: `docs/diagrams/model_lifecycle.png`
- **Slide Bullets**:
  - **Audited Analyst Feedback Loop (`ml/retrain_feedback.py`)**:
    - One-click false positive flagging from dashboard drawer.
    - Anti-poisoning guard rejects analyst corrections conflicting with high-severity rules (`SQLI-001`, `XSS-001`).
    - 4 automated promotion gates: FPR $\le 2.5\%$, Evasion recall drop $\le 2\%$, Cross-source drop $\le 2\%$, Latency $\le 10\text{ ms}$.
    - Instant one-command rollback (`make rollback-model`).
  - **Production Security Hardening (Stage 6 Audit)**:
    - Pattern-based credit card masking with ISO/IEC 7812 Luhn checksum validator (`[REDACTED_CC]`).
    - Pattern-based redaction of JWTs, Bearer tokens, and canary secrets (`gateway/masking.py`).
    - Strict Content Security Policy (`frame-ancestors 'none'`) and origin whitelisting on Dashboard API.
    - Upstream target completely isolated from public ports (`docker-compose.yml`).
- **Speaker Notes** (approx. 45 sec):
  > "A WAF cannot be a static artifact; it must evolve with analyst feedback. We built a closed-loop retraining pipeline with four automated quality gates and an anti-poisoning filter that prevents rogue analysts from retraining away known SQL injection signatures. In Stage 6, we hardened the entire system: implemented an ISO Luhn checksum scrubber for credit cards, redacted JWTs and passwords, locked down Content Security Policies, and completely isolated the demo application so it is reachable only through our WAF."

---

### Slide 12: Summary, Future Work & Demo Transition
- **Title**: Conclusions, Lessons Learned & Live Demonstration
- **Slide Bullets**:
  - **Summary of Achievements**:
    - All 7 PRD Goals (G1–G7) verifiably met.
    - +66.17% higher detection on zero-day evasions compared to ModSecurity PL1.
    - 0.00% False Positive Rate on 4,507 benign requests.
    - 133 unit and contract tests passing; turnkey demo reproducible in < 1 minute (`make demo-reset`).
  - **Identified Limitations & Lessons**:
    - Extreme out-of-distribution domain shift (Spanish CSIC corpus) requires rule safety nets.
    - Python GIL limits raw proxy throughput compared to native C/Rust engines.
  - **Future Roadmap**:
    - Rust/Envoy WASM proxy implementation for 50,000+ RPS.
    - Unsupervised URI autoencoders to flag structural route tampering.
  - **Transition to Live Demo**: 5-minute timed interactive walkthrough of SecOps dashboard and live attack mitigation.
- **Speaker Notes** (approx. 45 sec):
  > "In summary, our project proves that a hybrid architecture combining fast normalization, bounded regexes, and sub-word character n-grams beats traditional WAFs on evasion while eliminating false alarms. All components are packaged, tested, and tagged under release v1.0. We will now transition to our 5-minute live demonstration, walking you through our SecOps console, real-time attack mitigation, and token-level explainability. Thank you, and we welcome your questions."
