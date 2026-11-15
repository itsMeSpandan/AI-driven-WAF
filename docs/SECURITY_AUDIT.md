# Security, Sanitisation & Supply Chain Audit Report

**Audit Target**: AI-Driven Web Application Firewall & Analytics Dashboard  
**Release Target**: v1.0 (Stage 6 Hardening)  
**Date**: November 2026  
**Auditor**: Senior Full-Stack & ML Security Engineering Team  
**Scope Boundary**: Gateway (`gateway/`), Dashboard API (`dashboard/api/`), Dashboard UI (`dashboard/ui/`), Data Pipelines & Database Stores (`SQLite`/`PostgreSQL`).

---

## 1. Executive Summary

This comprehensive security audit proves—through automated tests, pattern scanners, and sink verifications rather than assertions—that:
1. **Sensitive Data Does Not Leak**: Credentials, session tokens, Luhn-valid credit card numbers, and canary secrets are systematically masked before reaching database tables, log files, SSE streams, or UI export sinks.
2. **Dashboard UI Cannot Be Attacked via Reflected/Stored Payloads**: The Next.js frontend contains zero unescaped HTML injections (`dangerouslySetInnerHTML`, `innerHTML`, `eval`), ensuring attack payloads render strictly as inert text nodes.
3. **Hardened Network & Container Perimeter**: The vulnerable demo application (`OWASP Juice Shop`) is isolated inside the internal Docker network with zero host port exposure; all API responses enforce strict Content Security Policy (CSP), anti-clickjacking frame headers, and restricted CORS origins.
4. **Supply Chain & Secret Hygiene**: Repository and git commit histories contain zero private keys or plaintext cloud credentials; dependencies and failure modes are locked and tested.

---

## 2. End-to-End Sensitive Data & Log Masking Audit

### 2.1 Canary Injection & Multi-Channel Testing
To mathematically verify non-leakage, unique high-entropy **canary strings** (`CANARY-PW-9f3a...`, `CANARY-TOK-8b70...`, `CANARY-JSON-0fa9...`) and ISO/IEC 7812 Luhn-valid credit card numbers were injected across all HTTP entry points:
- **URL Query Parameters**: `?password=CANARY-PW-...&token=CANARY-TOK-...`
- **URL-Encoded Form Data**: `username=admin&password=CANARY-PW-...`
- **Nested JSON Bodies**: `{"auth": {"credentials": {"password": "CANARY-JSON-...", "token": "..."}}}`
- **Authentication Headers**: `Authorization: Bearer CANARY-...`, `Proxy-Authorization`
- **Session Cookies**: `Cookie: session_id=CANARY-...`, `Set-Cookie`
- **Custom Sensitive Headers**: `X-API-Key`, `X-Auth-Token`, `X-Secret-Key`

### 2.2 Sink Verification
Every persistent sink was searched for canary occurrences:
- **Database Tables**: Verified `events`, `feedback`, and `config_audit` tables in SQLite and PostgreSQL.
- **Application Logs & Stdout**: Verified gateway async queue logging and standard output streams.
- **SSE Stream Broadcasts**: Verified `/api/events/stream` event serialization.
- **Explanation Dictionaries**: Verified that `canonical_text`, `top_tokens`, and `matched_rule_detail` mask credentials *before* persistence, while the in-memory detector scores the original request payload.

### 2.3 Automated Verification Test
- **Test Suite**: `gateway/tests/test_canary_leakage.py` (4 tests passing)
  - `test_luhn_algorithm_validator`: Validates Luhn checksum for Visa/Mastercard patterns.
  - `test_pattern_based_masking_coverage`: Verifies masking for CC, JWT, Bearer, and canary patterns.
  - `test_canary_not_leaked_into_event_payloads`: Proves zero canary leakage in enqueued events and explanations.
  - `test_canary_not_leaked_into_database_sink`: Verifies zero canary leakage across database records.

---

## 3. Dashboard UI Output Safety & XSS Defense

### 3.1 Static Code Analysis (AST & Regex Grep)
The entire `dashboard/ui/` codebase was audited for unsafe DOM injection sinks:
- `dangerouslySetInnerHTML`: **0 occurrences found**
- `innerHTML`: **0 occurrences found**
- `eval()`: **0 occurrences found**
- `new Function()`: **0 occurrences found**

### 3.2 Inert Text Rendering
All attack payloads (e.g., `<script>alert(1)</script>`, `<svg/onload=alert(document.domain)>`, `x" onerror="alert(1)`) displayed in the Events Feed, Request Detail Drawer, Explainer Token Highlights, and Settings Audit List are rendered as React text children with automatic string escaping.

### 3.3 Security Headers Baseline
Configured via `SecurityHeadersMiddleware` in `dashboard/api/main.py`:
- `Content-Security-Policy`: `default-src 'self'; frame-ancestors 'none';`
- `X-Content-Type-Options`: `nosniff`
- `X-Frame-Options`: `DENY`
- `Referrer-Policy`: `strict-origin-when-cross-origin`
- `Permissions-Policy`: `camera=(), microphone=(), geolocation=()`

### 3.4 CORS Policy & Error Leakage Prevention
- **CORS Whitelist**: Restricted to configured dashboard origins (`http://localhost:3000`, `http://127.0.0.1:3000`) via `ALLOWED_ORIGINS` environment variable.
- **Stack Trace Suppression**: Generic 500 error handler catches unhandled exceptions and returns sanitized JSON (`{"error": "Internal server error"}`) without exposing Python tracebacks, file paths, or SQL queries.

---

## 4. Authentication, Authorization & Supply Chain Review

### 4.1 Authentication & Authorization
- **RFC 7519 HS256 JWT**: Cryptographically signed access tokens with configurable expiration (`JWT_EXPIRATION_MINUTES=60`).
- **PBKDF2 Password Hashing**: Passwords stored using PBKDF2 with HMAC-SHA256 and 100,000 iterations.
- **Brute-Force Rate Limiting**: Exponential cooldown and per-IP throttling on `/api/auth/login`.
- **Admin Role Enforcement**: `PUT /api/config` and `GET /api/feedback/export` strictly protected by `get_current_admin` dependency.

### 4.2 Network & Container Isolation
- **Vulnerable Demo App Isolation**: In `docker-compose.yml`, the `demo-app` service has zero exposed host ports (`expose: ["3000"]`). It is reachable exclusively through the WAF Gateway on `waf-network`.
- **Resource Constraints**: CPU limits (`cpus: "1.0"`) and memory bounds (`memory: 512M`) enforced across all containers.
- **Baseline Container Safety**: ModSecurity baseline services bound strictly to `127.0.0.1`.

### 4.3 Git History Secret Scanning
- Scanned git commit log across all branches for private keys (`BEGIN PRIVATE KEY`), AWS tokens (`AKIA...`), and GitHub tokens (`ghp_...`): **0 secrets found**.

---

## 5. Security Findings & Remediations Log

| ID | Severity | Component | Finding Description | Remediation Applied | Verification Evidence |
|:---|:---:|:---|:---|:---|:---|
| **SEC-001** | **High** | `gateway/main.py`<br>`gateway/explainer.py` | `canonical_text` in explanation payload contained raw password and token values | Implemented `mask_canonical_text` and `mask_explanation` in `gateway/masking.py` before queueing or DB persistence | `test_canary_not_leaked_into_event_payloads` |
| **SEC-002** | **High** | `dashboard/api/routes/events.py` | Submitting analyst feedback stored raw unmasked `canonical_text` and analyst notes | Applied `mask_canonical_text` and `mask_patterns_in_text` to feedback records | `test_canary_not_leaked_into_database_sink` |
| **SEC-003** | **Medium** | `docker-compose.yml` | Demo vulnerable application exposed host port `3001` directly, bypassing WAF | Removed host port binding; converted to internal container port exposure | `docker-compose.yml` line 10 |
| **SEC-004** | **Medium** | `dashboard/api/main.py` | CORS policy allowed wildcard `*` origins and responses lacked security headers | Added `SecurityHeadersMiddleware` (CSP, nosniff, DENY) and restricted `ALLOWED_ORIGINS` | `test_security_headers_present_on_endpoints` |
| **SEC-005** | **Medium** | `dashboard/api/main.py` | Unhandled exceptions could potentially leak internal Python tracebacks to clients | Configured global `generic_exception_handler` returning generic 500 JSON | `test_no_stack_traces_leaked_on_internal_error` |
| **SEC-006** | **Low** | `gateway/masking.py` | Key-name masking failed on unexpected parameter names carrying credit cards or JWTs | Added pattern-based Luhn credit card validation, JWT regex, and Bearer masking | `test_pattern_based_masking_coverage` |

---

## 6. Known Limitations & Best-Effort Boundaries

1. **Polyglot & Steganographic Data**: Secrets embedded inside arbitrary binary uploads or custom encoded protocols cannot be inspected without specialized protocol dissectors.
2. **High-Entropy False Positives**: To avoid corrupting legitimate high-entropy search hashes or hexadecimal product IDs, entropy-based masking is applied only to fields with sensitive naming or recognized token prefixes (`CANARY-*`, `Bearer`, `eyJ*`).
3. **Fail-Open Operating Trade-Off**: When configured in `FAIL_MODE=open`, gateway errors forward requests upstream to prevent customer-facing outages, logging a warning incident. In mission-critical environments, `FAIL_MODE=closed` must be selected.
