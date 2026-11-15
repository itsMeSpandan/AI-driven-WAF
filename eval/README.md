# Stage 5 — Evaluation & Benchmarking vs ModSecurity + OWASP CRS

This directory contains the comparative evaluation framework, replay harnesses, latency benchmarks, raw request corpora, and evaluation results.

---

## 1. Baseline Configuration (ModSecurity + OWASP CRS)

To ensure an academically rigorous, fair comparison with no hidden advantages:
- **Official Pinned Image**: `owasp/modsecurity-crs:4.8.0-apache-202410200812`
- **Rule Engine**: Mode `On` (blocking)
- **Engine Ruleset**: OWASP Core Rule Set (CRS) v4
- **Headline Paranoia Level**: **Paranoia Level 1 (PL 1)**
  - Inbound Anomaly Threshold: `5`
  - Outbound Anomaly Threshold: `4`
- **Sensitivity Analysis**: **Paranoia Level 2 (PL 2)**
  - Evaluated on port `8082` to demonstrate the precision/recall trade-off
- **Audit Logging**: Formatted as JSON (`SecAuditLogFormat JSON`, `SecAuditEngine RelevantOnly`) mounted at `/var/log/apache2/modsec_audit.log`
- **Inspection Body Cap**: `16,384` bytes (`SecRequestBodyLimit 16384`), identical to `MAX_BODY_INSPECT_BYTES` on the AI-WAF gateway
- **Resource Limits**: Pinned identical to `waf-gateway` (`cpus: "1.0"`, `memory: 512M`)

---

## 2. Directory Layout

```
eval/
├── corpora/                     # Replayable raw HTTP requests (JSONL)
│   ├── README.md                # Documentation of injection templates
│   ├── test.jsonl               # In-distribution test requests
│   ├── evasion_test.jsonl       # Unseen Family B adversarial evasions
│   ├── evasion_familyA.jsonl    # Seen Family A evasions
│   ├── cross_source.jsonl       # Out-of-distribution CSIC 2010 requests
│   ├── benign_obfuscated.jsonl  # Obfuscated benign queries
│   ├── neutral.jsonl            # Neutral independent attack corpus
│   └── large_benign.jsonl       # Large benign corpus for tight FPR CI
├── modsec/                      # ModSecurity configuration & audit logs
│   ├── custom-audit.conf        # JSON audit logging directives
│   ├── modsec-pl1-audit.log     # PL1 transaction audit log
│   └── modsec-pl2-audit.log     # PL2 transaction audit log
├── results/                     # Benchmark results & raw telemetry
│   ├── raw/                     # Raw per-request CSV results
│   ├── detection.md             # Complete detection quality report
│   ├── detection.json           # Machine-readable detection metrics
│   ├── performance.md           # Latency and throughput benchmark report
│   ├── performance.json         # Machine-readable latency metrics
│   └── interpretability.md      # SHAP / token attribution analysis
├── figures/                     # ROC curves, confusion matrices, trade-offs
├── smoke_baseline.py            # Baseline smoke test script
├── benchmark_dual_proxy.py      # Dual-proxy replay harness with Wilson CIs
└── benchmark_perf.py            # Multithreaded concurrency & throughput benchmark
```

---

## 3. Running the Evaluation Suite

You can execute the entire evaluation pipeline with a single command:

```bash
# Run complete evaluation suite across all 7 corpora & benchmarks
make eval

# Or run the rapid evaluation suite (< 60s sample)
make eval-quick
```

Individual evaluation scripts can also be invoked directly:
```bash
# Baseline smoke test
python eval/smoke_baseline.py

# Replay corpora benchmark (computes Wilson 95% CIs & overlap analysis)
python eval/benchmark_dual_proxy.py

# Concurrency & latency benchmark (10, 50, 100 clients)
python eval/benchmark_perf.py

# Feature attribution & SHAP interpretability validation
python eval/shap_analysis.py

# Generate publication-ready figures
python eval/generate_figures.py
```
