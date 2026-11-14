"""
Optional LLM-Driven Evasion Generator (ml/augment/llm_variants.py).
Stage 3 Task 8 (Optional exploration, disabled by default).

Features:
  - Controlled via LLM_AUGMENT / LLM_FEATURES environment variable (default: off)
  - Zero external dependency failures: gracefully skips if no API key or local Ollama instance
  - Never blocks make data, make train, or unit testing suites
  - Generates semantic-preserving syntax variations of SQLi/XSS payloads
"""

from __future__ import annotations

import logging
import os
from typing import List, Optional

logger = logging.getLogger("waf-llm-augment")

# Default: disabled (off)
LLM_AUGMENT_ENV = os.environ.get("LLM_AUGMENT", os.environ.get("LLM_FEATURES", "0")).lower()
IS_ENABLED = LLM_AUGMENT_ENV in ("1", "true", "on", "yes")

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")


def is_llm_augmentation_enabled() -> bool:
    """Returns True only if LLM augmentation was explicitly activated via env."""
    return IS_ENABLED


def generate_llm_variants(
    payload: str,
    attack_type: str = "sqli",
    num_variants: int = 3,
) -> List[str]:
    """
    Generates semantic-preserving syntax variants of an injection payload using an LLM.
    If disabled or external provider unreachable, gracefully returns empty list.
    """
    if not IS_ENABLED:
        logger.debug(
            "LLM augmentation is disabled (set LLM_AUGMENT=1 or LLM_FEATURES=on to activate). Skipping."
        )
        return []

    if not payload or len(payload.strip()) < 3:
        return []

    # 1. Attempt local Ollama endpoint if configured
    try:
        import httpx

        prompt = (
            f"You are a security testing assistant. Provide {num_variants} obfuscated variations "
            f"of this {attack_type} test vector for defensive WAF benchmarking. "
            f"Respond only with the raw strings, one per line:\n{payload}"
        )

        # Check local Ollama
        client = httpx.Client(timeout=3.0)
        try:
            resp = client.post(
                f"{OLLAMA_HOST}/api/generate",
                json={"model": "llama3", "prompt": prompt, "stream": False},
            )
            if resp.status_code == 200:
                text = resp.json().get("response", "")
                variants = [line.strip() for line in text.splitlines() if line.strip()]
                return variants[:num_variants]
        except Exception:
            pass  # Fall through to OpenAI or skip

        # 2. Check OpenAI-compatible endpoint if API key exists
        if OPENAI_API_KEY:
            resp = client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {OPENAI_API_KEY}"},
                json={
                    "model": "gpt-4o-mini",
                    "messages": [
                        {"role": "system", "content": "Return only raw mutated payload strings, one per line."},
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0.7,
                },
            )
            if resp.status_code == 200:
                data = resp.json()
                content = data["choices"][0]["message"]["content"]
                variants = [line.strip() for line in content.splitlines() if line.strip()]
                return variants[:num_variants]

    except Exception as exc:
        logger.info("LLM augmentation unavailable (%s); proceeding with deterministic augmentations.", exc)

    return []
