"""
Evasion mutation engine for robustness and adversarial evaluation.
Implements Stage 3 Task 1 per TRD 2.3 & STAGES.md:
  - Deterministic, seeded composable mutation functions
  - Strictly disjoint mutation families:
      * Family A (Training families): Case folding, inline comments, whitespace, single URL-encode, operator swaps.
      * Family B (Held-out Evaluation families): Double URL-encode, HTML/hex entities, string concatenation, obscure tags/handlers, compound chaining.
  - Normalisation absorption measurement against waf_common.normalizer.
"""

from __future__ import annotations

import html
import random
import re
import urllib.parse
from typing import Callable, Dict, List, Optional, Set, Tuple

# Re-use shared normalizer for absorption measurement
from waf_common.normalizer import normalise_request

# ==============================================================================
# Helper Utilities & Seeded RNG
# ==============================================================================

def _get_rng(seed: Optional[int] = None) -> random.Random:
    return random.Random(seed)


def _random_case(text: str, rng: random.Random) -> str:
    """Randomly flips case of alphabetical characters deterministically."""
    return "".join(c.upper() if rng.choice([True, False]) else c.lower() for c in text)


# ==============================================================================
# Family A: Training Mutation Functions (Malicious SQLi)
# ==============================================================================

def mutate_sqli_case(payload: str, rng: random.Random) -> str:
    """Randomizes case of SQL keywords like SELECT, UNION, WHERE, OR, AND."""
    keywords = ["select", "union", "where", "from", "or", "and", "like", "order by", "group by", "sleep", "benchmark"]
    result = payload
    for kw in keywords:
        pattern = re.compile(rf"\b{kw}\b", re.IGNORECASE)
        matches = list(pattern.finditer(result))
        for m in reversed(matches):
            cased = _random_case(m.group(0), rng)
            result = result[: m.start()] + cased + result[m.end() :]
    if result == payload:
        # Fallback to general randomized case
        result = _random_case(payload, rng)
    return result


def mutate_sqli_inline_comments(payload: str, rng: random.Random) -> str:
    """Inserts SQL inline comments (/**/) into spaces or keywords."""
    if " " in payload:
        parts = payload.split(" ")
        comment = rng.choice(["/**/", "/*dummy*/", "/*x*/"])
        return comment.join(parts)
    # Split keywords with comments
    for kw in ["union", "select", "from", "where"]:
        if kw in payload.lower():
            idx = payload.lower().find(kw) + len(kw) // 2
            return payload[:idx] + "/**/" + payload[idx:]
    return payload + "/**/"


def mutate_sqli_whitespace(payload: str, rng: random.Random) -> str:
    """Substitutes standard spaces with tabs, newlines, or multiple spaces."""
    substitutes = ["\t", "\n", "  ", "   ", "+"]
    choice = rng.choice(substitutes)
    if " " in payload:
        return payload.replace(" ", choice)
    return payload + choice


def mutate_sqli_url_encode(payload: str, rng: random.Random) -> str:
    """Applies standard single URL-encoding to special characters."""
    # Encode quotes, spaces, and operators
    safe_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    encoded = "".join(
        f"%{ord(c):02X}" if (c not in safe_chars and rng.choice([True, False])) else c
        for c in payload
    )
    if encoded == payload:
        encoded = urllib.parse.quote(payload)
    return encoded


def mutate_sqli_operator_swap(payload: str, rng: random.Random) -> str:
    """Swaps SQL operators for syntactic equivalents (e.g. OR -> ||, = -> LIKE)."""
    result = payload
    # Swap 'OR' with '||'
    if re.search(r"\bOR\b", result, re.IGNORECASE):
        result = re.sub(r"\bOR\b", "||", result, flags=re.IGNORECASE)
    elif re.search(r"\bAND\b", result, re.IGNORECASE):
        result = re.sub(r"\bAND\b", "&&", result, flags=re.IGNORECASE)
    elif "=" in result and rng.choice([True, False]):
        result = result.replace("=", " LIKE ")
    return result


# ==============================================================================
# Family A: Training Mutation Functions (Malicious XSS)
# ==============================================================================

def mutate_xss_case(payload: str, rng: random.Random) -> str:
    """Randomizes case of HTML tags and attribute names."""
    tags = ["script", "img", "svg", "iframe", "body", "input", "onload", "onerror", "onclick", "alert"]
    result = payload
    for tag in tags:
        pattern = re.compile(rf"{tag}", re.IGNORECASE)
        matches = list(pattern.finditer(result))
        for m in reversed(matches):
            cased = _random_case(m.group(0), rng)
            result = result[: m.start()] + cased + result[m.end() :]
    if result == payload:
        result = _random_case(payload, rng)
    return result


def mutate_xss_quote_whitespace(payload: str, rng: random.Random) -> str:
    """Substitutes quote styles (backticks/single quotes) and whitespace in tags."""
    result = payload
    if '"' in result:
        result = result.replace('"', "'")
    elif "'" in result:
        result = result.replace("'", "`")
    # Insert slash whitespace inside tags e.g. <img/src=x/onerror=...>
    if " " in result and "<" in result:
        result = result.replace(" ", "/")
    return result


def mutate_xss_url_encode(payload: str, rng: random.Random) -> str:
    """Standard single URL encoding for XSS characters (<, >, quotes)."""
    encoded = ""
    for c in payload:
        if c in "<>\"' ()":
            encoded += f"%{ord(c):02X}" if rng.choice([True, False]) else c
        else:
            encoded += c
    if encoded == payload:
        encoded = urllib.parse.quote(payload)
    return encoded


def mutate_xss_event_handler(payload: str, rng: random.Random) -> str:
    """Swaps standard script tags or event handlers with alternative event handlers."""
    handlers = ["onerror", "onload", "onmouseover", "onfocus", "ontoggle", "onpointerdown"]
    chosen_handler = rng.choice(handlers)
    if "onerror" in payload.lower():
        return re.sub(r"onerror", chosen_handler, payload, flags=re.IGNORECASE)
    elif "onload" in payload.lower():
        return re.sub(r"onload", chosen_handler, payload, flags=re.IGNORECASE)
    elif "<script>" in payload.lower():
        return payload.replace("<script>", f"<img src=x {chosen_handler}=").replace("</script>", ">")
    return payload


# ==============================================================================
# Family A: Benign Obfuscation Functions (Protects FPR)
# ==============================================================================

def mutate_benign_url_encode(text: str, rng: random.Random) -> str:
    """URL encodes harmless query parameter values or paths."""
    if "=" in text:
        k, v = text.split("=", 1)
        return f"{k}={urllib.parse.quote(v)}"
    return urllib.parse.quote(text, safe="/?")


def mutate_benign_case(text: str, rng: random.Random) -> str:
    """Randomizes casing of benign parameters or paths."""
    return _random_case(text, rng)


def mutate_benign_whitespace(text: str, rng: random.Random) -> str:
    """Adds harmless padding, double spaces, or trailing slashes."""
    choices = [text + " ", text + "/", text.replace(" ", "  ") if " " in text else text + "  "]
    return rng.choice(choices)


# ==============================================================================
# Family B: Held-Out Evaluation Mutation Functions (Adversarial / Evasion Only)
# ==============================================================================

def mutate_sqli_double_url_encode(payload: str, rng: random.Random) -> str:
    """Applies double URL encoding (%2527 for single quote, %2520 for space)."""
    single = urllib.parse.quote(payload)
    double = urllib.parse.quote(single)
    # Ensure double encoded hex markers (%25) are present
    return double


def mutate_sqli_hex_literal(payload: str, rng: random.Random) -> str:
    """Replaces string literals with SQL hexadecimal representations e.g. 'admin' -> 0x61646d696e."""
    match = re.search(r"['\"]([a-zA-Z0-9_]+)['\"]", payload)
    if match:
        target_str = match.group(1)
        hex_val = "0x" + target_str.encode("utf-8").hex()
        return payload[: match.start()] + hex_val + payload[match.end() :]
    # Fallback: append hex literal comparison
    return payload + " and 0x61=0x61"


def mutate_sqli_concat_tricks(payload: str, rng: random.Random) -> str:
    """Splits string literals using SQL CONCAT function or string pipe concatenation."""
    match = re.search(r"['\"]([a-zA-Z0-9_]{3,})['\"]", payload)
    if match:
        target_str = match.group(1)
        half = len(target_str) // 2
        part1, part2 = target_str[:half], target_str[half:]
        concat_expr = f"CONCAT('{part1}','{part2}')"
        return payload[: match.start()] + concat_expr + payload[match.end() :]
    return payload + " /*concat*/"


def mutate_xss_double_url_encode(payload: str, rng: random.Random) -> str:
    """Applies double URL encoding to HTML tags and quotes (%253C for <)."""
    single = urllib.parse.quote(payload)
    return urllib.parse.quote(single)


def mutate_xss_html_entity_hex(payload: str, rng: random.Random) -> str:
    """Encodes characters as hexadecimal HTML entities (e.g. &#x3c; for <, &#x6a; for j)."""
    result = ""
    for c in payload:
        if c in "<>'\"javascript:()":
            result += f"&#x{ord(c):02x};"
        else:
            result += c
    return result


def mutate_xss_char_code(payload: str, rng: random.Random) -> str:
    """Replaces string arguments with JavaScript String.fromCharCode expressions."""
    match = re.search(r"\b(alert|prompt|confirm)\((['\"][^'\"]+['\"])\)", payload)
    if match:
        fn_name = match.group(1)
        arg_str = match.group(2).strip("'\"")
        char_codes = ",".join(str(ord(c)) for c in arg_str)
        replacement = f"{fn_name}(String.fromCharCode({char_codes}))"
        return payload[: match.start()] + replacement + payload[match.end() :]
    return payload.replace("alert(1)", "alert(String.fromCharCode(49))")


def mutate_xss_obscure_tags(payload: str, rng: random.Random) -> str:
    """Injects obscure or modern HTML5 tags like <details ontoggle=...>, <audio src onerror=...>."""
    obscure_tags = [
        "<details open ontoggle=alert(1)>",
        "<audio src=1 onerror=alert(1)>",
        "<video><source onerror=alert(1)>",
        "<svg/onload=alert(1)>",
    ]
    return rng.choice(obscure_tags)


def mutate_compound_evasion(payload: str, rng: random.Random) -> str:
    """Chains multiple Family B mutations for complex obfuscation."""
    # E.g. entity encoding + comment split + double url encoding
    res = payload
    if "<" in res:
        res = mutate_xss_html_entity_hex(res, rng)
        res = mutate_xss_double_url_encode(res, rng)
    else:
        res = mutate_sqli_inline_comments(res, rng)
        res = mutate_sqli_double_url_encode(res, rng)
    return res


# ==============================================================================
# Family Dispatch Registry
# ==============================================================================

FAMILY_A_SQLI: List[Callable[[str, random.Random], str]] = [
    mutate_sqli_case,
    mutate_sqli_inline_comments,
    mutate_sqli_whitespace,
    mutate_sqli_url_encode,
    mutate_sqli_operator_swap,
]

FAMILY_A_XSS: List[Callable[[str, random.Random], str]] = [
    mutate_xss_case,
    mutate_xss_quote_whitespace,
    mutate_xss_url_encode,
    mutate_xss_event_handler,
]

FAMILY_A_BENIGN: List[Callable[[str, random.Random], str]] = [
    mutate_benign_url_encode,
    mutate_benign_case,
    mutate_benign_whitespace,
]

FAMILY_B_SQLI: List[Callable[[str, random.Random], str]] = [
    mutate_sqli_double_url_encode,
    mutate_sqli_hex_literal,
    mutate_sqli_concat_tricks,
    mutate_compound_evasion,
]

FAMILY_B_XSS: List[Callable[[str, random.Random], str]] = [
    mutate_xss_double_url_encode,
    mutate_xss_html_entity_hex,
    mutate_xss_char_code,
    mutate_xss_obscure_tags,
    mutate_compound_evasion,
]

FAMILY_B_BENIGN: List[Callable[[str, random.Random], str]] = [
    # Benign obfuscation variants corresponding to Family B styles
    lambda text, rng: urllib.parse.quote(urllib.parse.quote(text, safe=""), safe=""),  # double encode
    lambda text, rng: html.escape(text),  # HTML entity encoding on benign text
]


# ==============================================================================
# Public API
# ==============================================================================

def mutate_payload(
    payload: str,
    family: str = "A",
    attack_type: str = "sqli",
    seed: Optional[int] = None,
) -> str:
    """
    Mutate a payload deterministically given family ('A' or 'B') and attack_type ('sqli', 'xss', 'benign').
    Guarantees deterministic output for a given seed.
    """
    rng = _get_rng(seed)

    if family.upper() == "A":
        if attack_type == "sqli":
            mutator = rng.choice(FAMILY_A_SQLI)
        elif attack_type == "xss":
            mutator = rng.choice(FAMILY_A_XSS)
        else:
            mutator = rng.choice(FAMILY_A_BENIGN)
    elif family.upper() == "B":
        if attack_type == "sqli":
            mutator = rng.choice(FAMILY_B_SQLI)
        elif attack_type == "xss":
            mutator = rng.choice(FAMILY_B_XSS)
        else:
            mutator = rng.choice(FAMILY_B_BENIGN)
    else:
        raise ValueError(f"Unknown mutation family: '{family}'. Must be 'A' or 'B'.")

    mutated = mutator(payload, rng)
    # Ensure mutated payload is not empty
    return mutated if mutated.strip() else payload


def measure_normalisation_absorption(
    samples: List[Tuple[str, str]],
    family: str = "A",
    seed: int = 42,
) -> Dict[str, float]:
    """
    Applies mutation to sample payloads, passes through normalise_request(),
    and calculates the absorption rate:
      - Absorbed: normalise(mutated) == normalise(original)
      - Survived: normalise(mutated) != normalise(original)
    Returns:
      {
        "total_tested": int,
        "absorbed_count": int,
        "survived_count": int,
        "absorption_rate": float (0.0 to 1.0),
        "survival_rate": float (0.0 to 1.0)
      }
    """
    rng = _get_rng(seed)
    absorbed = 0
    survived = 0

    for raw_text, attack_type in samples:
        orig_norm = normalise_request("GET", "/test", raw_text, {}, b"").canonical_text
        mutated_text = mutate_payload(raw_text, family=family, attack_type=attack_type, seed=rng.randint(0, 100000))
        mut_norm = normalise_request("GET", "/test", mutated_text, {}, b"").canonical_text

        if orig_norm == mut_norm:
            absorbed += 1
        else:
            survived += 1

    total = len(samples)
    abs_rate = absorbed / total if total > 0 else 0.0
    surv_rate = survived / total if total > 0 else 0.0

    return {
        "total_tested": total,
        "absorbed_count": absorbed,
        "survived_count": survived,
        "absorption_rate": round(abs_rate, 4),
        "survival_rate": round(surv_rate, 4),
    }
