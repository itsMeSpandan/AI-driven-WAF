# Rule-Only Baseline False Positive Rate (FPR) Report

**Date:** 2026-11-15
**Corpus Size:** 1,565 verified benign requests
**Active Rules:** 29 signatures
**Measured Rule-Only FPR:** `0.00%` (0 / 1565)

---

## 1. Rule Hit Breakdown on Benign Traffic

| Rule ID | Category | Severity | Description | False Hits | Hit Rate on Benign |
|---|---|---|---|---|---|
| `SQLI-001` | sqli | critical | Boolean-based tautology: OR 1=1 / OR '1'='1' | 0 | 0.00% |
| `SQLI-002` | sqli | critical | UNION-based data exfiltration query | 0 | 0.00% |
| `SQLI-003` | sqli | critical | Destructive DDL/DML statement: DROP / ALTER / TRUNCATE | 0 | 0.00% |
| `SQLI-004` | sqli | high | SQL comment dash syntax used for query truncation | 0 | 0.00% |
| `SQLI-005` | sqli | critical | System schema extraction: information_schema | 0 | 0.00% |
| `SQLI-006` | sqli | high | Time-based blind injection: sleep() / benchmark() / waitfor | 0 | 0.00% |
| `SQLI-007` | sqli | high | Stacked SQL query delimiter | 0 | 0.00% |
| `SQLI-008` | sqli | high | File system exfiltration via load_file or into outfile | 0 | 0.00% |
| `SQLI-009` | sqli | medium | SQL hexadecimal literal pattern | 0 | 0.00% |
| `SQLI-010` | sqli | high | Authentication bypass: admin quote dash | 0 | 0.00% |
| `XSS-001` | xss | critical | Explicit script tag injection | 0 | 0.00% |
| `XSS-002` | xss | high | Script closing tag | 0 | 0.00% |
| `XSS-003` | xss | high | HTML onload event handler injection | 0 | 0.00% |
| `XSS-004` | xss | high | HTML onerror event handler injection | 0 | 0.00% |
| `XSS-005` | xss | high | Interactive event handlers (onclick, onmouseover, onfocus) | 0 | 0.00% |
| `XSS-006` | xss | critical | javascript: pseudo-protocol URI | 0 | 0.00% |
| `XSS-007` | xss | high | vbscript: pseudo-protocol URI | 0 | 0.00% |
| `XSS-008` | xss | high | Embedded iframe element tag | 0 | 0.00% |
| `XSS-009` | xss | high | SVG with embedded event handler | 0 | 0.00% |
| `XSS-010` | xss | medium | Execution of alert(), prompt(), or confirm() modal calls | 0 | 0.00% |
| `XSS-011` | xss | high | DOM cookie / location exfiltration reference | 0 | 0.00% |
| `TRAV-001` | path_traversal | critical | Directory traversal sequence (../ or ..\) | 0 | 0.00% |
| `TRAV-002` | path_traversal | critical | Linux sensitive file probe (/etc/passwd, /etc/shadow) | 0 | 0.00% |
| `TRAV-003` | path_traversal | critical | Windows system directory probe (system32/cmd.exe) | 0 | 0.00% |
| `CMD-001` | cmd_injection | critical | Command shell piping / chaining (; cat / ; whoami / ; id -u) | 0 | 0.00% |
| `CMD-002` | cmd_injection | critical | Direct shell interpreter invocation (/bin/sh, powershell, cmd.exe) | 0 | 0.00% |
| `SCAN-001` | scanner | high | Automated SQL injection scanner: sqlmap | 0 | 0.00% |
| `SCAN-002` | scanner | medium | Automated vulnerability scanner (Nikto, Acunetix, Nessus, Nmap) | 0 | 0.00% |
| `SCAN-003` | scanner | high | Sensitive environment and configuration file probes | 0 | 0.00% |

## 2. False Positive Samples Analysis

Zero false positives were observed on the clean benign corpus. The rule set maintains high specificity.

## 3. Findings & Mitigation
- The hybrid architecture utilizes the rule layer as a cheap first-pass filter for unambiguous attack syntax.
- Subtler, ambiguous requests with non-zero threat potential are delegated to the ML detector for nuanced probability scoring.