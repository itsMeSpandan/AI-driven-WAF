# Replayable Raw HTTP Evaluation Corpora

This directory contains deterministic, replayable raw HTTP request specifications (`.jsonl`) generated from the frozen evaluation splits by `eval/build_corpora.py`.

---

## 1. Corpora Summary

| Corpus File | Request Count | Malicious | Benign | Primary Purpose | Home-Field Status |
|---|---|---|---|---|---|
| `test.jsonl` | 2,526 | 1,019 | 1,507 | Standard in-distribution test set | **In-Distribution for AI-WAF** |
| `evasion_test.jsonl` | 857 | 857 | 0 | Unseen Family B zero-day mutations (hex, double urlencode, char codes, obscure HTML5 tags) | **Unseen by both** |
| `evasion_familyA.jsonl` | 1,019 | 1,019 | 0 | Seen Family A mutations (comments, whitespace, operator swap) | **Augmentation benchmark** |
| `benign_obfuscated.jsonl` | 1,507 | 0 | 1,507 | Benign requests with complex punctuation, symbols & encoding | **FPR under obfuscation** |
| `cross_source.jsonl` | 12,069 | 12,069 | 0 | Out-of-distribution Spanish CSIC 2010 anomalous requests | **Out-of-Distribution for both** |
| `neutral.jsonl` | 1,000 | 500 | 500 | Independent attack vectors (SQLi, XSS, Path Traversal, RCE, SSRF) + neutral eCommerce browsing | **Neutral / Favours neither** |
| `large_benign.jsonl` | 3,000 | 0 | 3,000 | Realistic user catalog search queries | **High-precision FPR CI** |

---

## 2. Deterministic Injection Templates

For textbook payloads, real HTTP requests are synthesized across 4 distinct web application channels:

1. **Channel 1 — Query Parameter (60% of requests)**:
   - Method: `GET`
   - Path: `/rest/products/search?q={url_encoded(payload)}`
   - Target Application: OWASP Juice Shop Product Search API
2. **Channel 2 — JSON Body Field (20% of requests)**:
   - Method: `POST`
   - Path: `/api/Feedbacks/`
   - Headers: `Content-Type: application/json`
   - Body: `{"comment": "{payload}", "rating": 5}`
3. **Channel 3 — Form Body Field (10% of requests)**:
   - Method: `POST`
   - Path: `/rest/user/login`
   - Headers: `Content-Type: application/x-www-form-urlencoded`
   - Body: `email={url_encoded(payload)}&password=SecOpsBenchPassword123!`
4. **Channel 4 — HTTP Header (10% of requests)**:
   - Method: `GET`
   - Path: `/rest/basket/1`
   - Headers: `User-Agent: {payload}`, `X-Forwarded-For: 198.51.100.24`

For `cross_source.jsonl` (CSIC 2010), requests are parsed and replayed with their native HTTP methods, paths, query strings, and form bodies.

---

## 3. Anti-Leakage & Cryptographic Invariance

- **Zero Overlap**: Every sample in `test.jsonl`, `evasion_test.jsonl`, `evasion_familyA.jsonl`, `benign_obfuscated.jsonl`, `cross_source.jsonl`, `neutral.jsonl`, and `large_benign.jsonl` was cryptographically verified against the active training set (`train_augmented.csv`). Zero collisions exist.
- **Deterministic**: The generator produces identical request IDs and byte payloads across repeated invocations.
