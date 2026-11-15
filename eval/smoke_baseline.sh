#!/usr/bin/env bash
# Smoke test script for ModSecurity + OWASP CRS baseline
set -euo pipefail

echo "=================================================================="
echo "    Executing Stage 5 Baseline Smoke Test (Bash Runner)          "
echo "=================================================================="

python eval/smoke_baseline.py
