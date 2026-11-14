# Evasion Mutation Engine & Adversarial Robustness

This package (`ml/augment/`) implements deterministic, composable payload mutations used to generate:
1. **Augmented Training Data**: Expands training coverage without dataset leakage.
2. **Adversarial Evasion Evaluation Sets**: Evaluates zero-day and unseen evasion techniques.

---

## 1. Disjoint Mutation Families

To ensure honest evaluation and avoid training on the test set, mutation functions are partitioned into **two strictly disjoint families**:

```
                       ┌────────────────────────────────────────────────┐
                       │               Mutation Engine                  │
                       └──────────────┬──────────────────┬──────────────┘
                                      │                  │
                                      ▼                  ▼
                       ┌──────────────────────┐ ┌──────────────────────┐
                       │   Family A (Train)   │ │  Family B (Held-Out) │
                       │   SEEN In Training   │ │  UNSEEN In Training  │
                       └──────────────────────┘ └──────────────────────┘
```

### Family A (Training Families)
*Used solely to augment the `train.csv` split. Never applied to `test.csv` for evasion reporting.*

- **SQLi**:
  - `mutate_sqli_case`: Random case folding of keywords (`sElEcT`, `uNiOn`, `wHeRe`).
  - `mutate_sqli_inline_comments`: SQL inline comments (`/**/`, `/*x*/`).
  - `mutate_sqli_whitespace`: Tab, newline, or multiple space substitutions.
  - `mutate_sqli_url_encode`: Single standard URL encoding (`%20`, `%27`, `%23`).
  - `mutate_sqli_operator_swap`: Syntactic synonym swaps (`OR` ↔ `||`, `AND` ↔ `&&`, `=` ↔ `LIKE`).
- **XSS**:
  - `mutate_xss_case`: Random case folding of tags (`<sCrIpT>`, `<iMg>`).
  - `mutate_xss_quote_whitespace`: Backtick and single quote substitutions, slash-delimited tags (`<img/src=x/onerror=...>`).
  - `mutate_xss_url_encode`: Standard single URL encoding of tag brackets and delimiters.
  - `mutate_xss_event_handler`: Alternative standard event handlers (`onload`, `onerror`, `onfocus`, `onmouseover`).
- **Benign Obfuscation** *(Vital for preserving FPR)*:
  - `mutate_benign_url_encode`: Standard URL encoding of benign parameter values and paths.
  - `mutate_benign_case`: Case variation in harmless query keys and paths.
  - `mutate_benign_whitespace`: Benign space padding and trailing slash additions.

---

### Family B (Held-Out Evaluation Families)
*Strictly prohibited from training and validation threshold tuning. Reserved exclusively for building `evasion_test.csv`.*

- **SQLi**:
  - `mutate_sqli_double_url_encode`: Double URL encoding (`%2527` for `'`, `%2520` for space).
  - `mutate_sqli_hex_literal`: Replaces string literals with SQL hexadecimal representations (`0x61646d696e`).
  - `mutate_sqli_concat_tricks`: SQL `CONCAT(...)` and string pipe splitting (`'adm'||'in'`).
  - `mutate_compound_evasion`: Multi-stage chained evasion combining comment splitting with double encoding.
- **XSS**:
  - `mutate_xss_double_url_encode`: Double URL encoding of tag delimiters (`%253C` for `<`).
  - `mutate_xss_html_entity_hex`: Hexadecimal HTML entities (`&#x3c;` for `<`, `&#x6a;` for `j`).
  - `mutate_xss_char_code`: Dynamic string reconstruction (`String.fromCharCode(...)`).
  - `mutate_xss_obscure_tags`: Modern or obscure HTML5 tags (`<details ontoggle=...>`, `<audio/video onerror=...>`).
  - `mutate_compound_evasion`: Compound chaining of entity encoding and double URL encoding.

---

## 2. Normalisation Absorption Analysis

The gateway includes an iterative normaliser (`waf_common/normalizer.py`) that performs:
- Up to 3 recursive URL decodings
- HTML entity unescaping
- Unicode NFKC normalization
- SQL inline comment removal (`/**/`)
- Whitespace collapse

### Absorption Characteristics:
- **Family A Absorption**: Many Family A mutations (such as simple inline comments `/**/`, single `%20` URL-encodings, and uppercase keywords) are intentionally collapsed by `normalise()`.
- **Evasion Survival**: Family B mutations (such as double URL encoding `%2527`, hexadecimal entity encoding, and `String.fromCharCode`) partially survive single-stage decoders and reach the ML detector as obfuscated canonical text.
- This creates the dual defensive layer: **Normalizer absorbs simple obfuscation; ML detector recognizes residual adversarial patterns.**
