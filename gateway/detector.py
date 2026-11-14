"""
Machine learning detector loader and inference runtime.
Implements Stage 2 Task 5 per TRD 2.2 & STAGES.md:
  - Loads model.joblib and metadata.json at startup
  - Checks library versions and logs warnings on mismatch
  - Exposes score(canonical_text) -> MLResult
  - Fail-safe fallback to rule-only mode if model is missing or unreadable
"""

from __future__ import annotations

import json
import logging
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import joblib

logger = logging.getLogger("waf-detector")

REPO_ROOT = Path(__file__).resolve().parent.parent
MODEL_PATH = REPO_ROOT / "ml" / "models" / "model.joblib"
METADATA_PATH = REPO_ROOT / "ml" / "models" / "metadata.json"

SQL_INDICATORS = re.compile(
    r"\b(select|union|drop|from|where|or|and|1=1|sleep|benchmark|insert|update|delete)\b",
    re.IGNORECASE,
)
XSS_INDICATORS = re.compile(
    r"(<\s*script|alert\s*\(|onerror\s*=|onload\s*=|javascript:|<\s*img|<\s*svg)",
    re.IGNORECASE,
)


@dataclass
class MLResult:
    score: float = 0.0
    attack_type: str = "benign"
    confidence: float = 0.0
    model_version: str = "none"


class MLDetector:
    def __init__(self, model_file: Optional[Path] = None, metadata_file: Optional[Path] = None):
        self.model_file = model_file or MODEL_PATH
        self.metadata_file = metadata_file or METADATA_PATH
        self.pipeline = None
        self.metadata = {}
        self.is_loaded = False
        self.model_version = "rule-only"
        self.calibrated_threshold = 0.26
        self.load()

    def load(self) -> None:
        """Attempt to load model pipeline and metadata with robust fail-safe."""
        if not self.model_file.exists():
            logger.warning(
                "[!] WAF DETECTOR WARNING: '%s' not found. "
                "Operating in RULE-ONLY mode. (Run 'make train' to generate model).",
                self.model_file,
            )
            self.is_loaded = False
            self.model_version = "rule-only"
            return

        try:
            self.pipeline = joblib.load(self.model_file)
            if self.metadata_file.exists():
                self.metadata = json.loads(self.metadata_file.read_text(encoding="utf-8"))
                self.model_version = self.metadata.get("model_version", "v1.0")
                self.calibrated_threshold = float(self.metadata.get("threshold", 0.26))

                # Check library version compatibility
                saved_sklearn = self.metadata.get("libraries", {}).get("scikit_learn")
                curr_sklearn = getattr(joblib, "__version__", None)
                if saved_sklearn and curr_sklearn and saved_sklearn != curr_sklearn:
                    logger.warning(
                        "Detector note: Model was saved with scikit-learn %s, current runtime is %s.",
                        saved_sklearn,
                        curr_sklearn,
                    )

            self.is_loaded = True
            logger.info(
                "Loaded ML model: %s (version: %s | default threshold: %.2f)",
                self.metadata.get("model_name", "Classifier"),
                self.model_version,
                self.calibrated_threshold,
            )
        except Exception as load_err:
            logger.error(
                "[!] WAF DETECTOR CRITICAL: Failed to load model: %s. "
                "Falling back to RULE-ONLY mode.",
                load_err,
            )
            self.is_loaded = False
            self.model_version = "rule-only-fallback"

    def score(self, canonical_text: str) -> MLResult:
        """
        Execute prediction on canonical text.
        Returns continuous threat score (0.0 to 1.0) and classified attack taxonomy.
        """
        if not self.is_loaded or self.pipeline is None or not canonical_text:
            return MLResult(
                score=0.0,
                attack_type="benign",
                confidence=0.0,
                model_version=self.model_version,
            )

        try:
            probs = self.pipeline.predict_proba([canonical_text])[0]
            # Probability of malicious class (label=1)
            malicious_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])

            # Classify attack taxonomy
            attack_type = "benign"
            if malicious_prob >= self.calibrated_threshold:
                if SQL_INDICATORS.search(canonical_text):
                    attack_type = "sqli"
                elif XSS_INDICATORS.search(canonical_text):
                    attack_type = "xss"
                else:
                    attack_type = "ml_anomaly"

            return MLResult(
                score=round(malicious_prob, 4),
                attack_type=attack_type,
                confidence=round(malicious_prob, 4),
                model_version=self.model_version,
            )
        except Exception as pred_err:
            logger.error("Error during ML scoring: %s", pred_err)
            return MLResult(score=0.0, attack_type="benign", confidence=0.0, model_version="error")


# Global detector instance
detector = MLDetector()
