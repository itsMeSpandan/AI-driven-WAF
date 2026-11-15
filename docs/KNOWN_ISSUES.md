# Known Issues, Limitations & Future Considerations

This document transparently lists all known limitations, operational edge cases, and architectural trade-offs identified during the Stage 5 evaluation and Stage 6 hardening phases of the AI-Driven WAF.

---

## 1. Machine Learning & Detection Boundaries

### Issue 1: Out-of-Distribution Domain Shift on Unseen Web Schemas (CSIC 2010)
- **Description**: When tested against the Spanish CSIC 2010 eCommerce dataset (`/tienda1/publico/anadir.jsp`), the ML detector alone achieves **1.18% recall** because token frequencies reflect an entirely different linguistic and application parameter schema than the training set.
- **Mitigation & Impact**: The hybrid architecture pairs the ML model with high-confidence regex signatures (`evaluate_rules`), raising composite recall to **20.29%** (higher than ModSecurity CRS PL1 at 15.15%).
- **Future Work**: Domain-adaptive transfer learning and unsupervised autoencoders for path anomaly detection.

### Issue 2: Deeply Nested Obfuscation & Dynamic Code Evaluation
- **Description**: Highly complex adversarial mutations (Family B) utilizing multi-stage JavaScript `String.fromCharCode` concatenation or non-standard hex literals can bypass character n-gram thresholds when token distributions resemble randomized strings.
- **Mitigation & Impact**: Preprocessing normalizer performs iterative URL unquoting (depth 3), HTML entity unescaping, and Unicode NFKC normalization prior to vectorization. The hybrid pipeline caught **90.32%** of Family B mutations (+66.17% over ModSecurity PL1).
- **Future Work**: Lightweight Abstract Syntax Tree (AST) parser for JavaScript and SQL expressions in the preprocessing pipeline.

---

## 2. Performance & Concurrency Scaling

### Issue 3: Python Global Interpreter Lock (GIL) Throughput Ceiling
- **Description**: Under heavy multithreaded client concurrency (100 concurrent clients), the pure Python FastAPI proxy achieves sustained throughput of **~600 RPS** per worker container when executing full ML scoring. ModSecurity's compiled C Apache module sustains higher throughput.
- **Mitigation & Impact**: Rules-only execution sustains **> 13,000 RPS** at 0.99 ms latency. In production, FastAPI gateways scale horizontally behind a Layer 4 load balancer (e.g., Envoy or HAProxy).
- **Future Work**: Export model to ONNX runtime or compiled C++/Rust proxy engine (e.g., Envoy WASM filter).

### Issue 4: Request Body Inspection Size Cap
- **Description**: Request body inspection is capped at **16,384 bytes** (`MAX_BODY_INSPECT_BYTES`). Payloads exceeding 16KB are inspected on the initial 16KB window, while the full body is forwarded upstream intact.
- **Mitigation & Impact**: Prevents polynomial memory spikes, denial-of-service, and ReDoS on multi-gigabyte file uploads. Attack payloads placed after 16KB in an oversized request body would bypass ML scoring.
- **Future Work**: Streaming chunk-based tokenization for multipart file uploads.

---

## 3. Data Sanitisation & Log Masking

### Issue 5: Best-Effort Masking on Custom Non-Standard Field Names
- **Description**: Sensitive data masking relies on standard keyword heuristics (`password`, `token`, `secret`, `api_key`, `credit_card`) and pattern recognizers (Luhn credit cards, JWTs, Bearer headers, Canaries). If a client transmits sensitive data under an obscure custom key (e.g. `x_custom_blob_99`) without matching pattern signatures, it may not be masked in logs.
- **Mitigation & Impact**: Pattern-based Luhn scanner and JWT detectors catch standard financial and authentication formats regardless of parameter key names.
- **Future Work**: NLP-based Named Entity Recognition (NER) pipeline for PII detection in asynchronous logging workers.
