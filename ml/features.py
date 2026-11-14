"""
Feature extraction pipeline for AI WAF detector.
Implements Stage 2 Task 2 per TRD 2.3 & STAGES.md:
  - Character n-gram TF-IDF (2-5, analyzer='char_wb', sublinear_tf=True, capped max_features)
  - Statistical lexical features (length, special-char ratio, digit ratio, entropy, keywords, XSS markers)
  - Unified sklearn FeatureUnion / Pipeline for single-artefact serialization
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import List, Sequence

import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import StandardScaler

# Set of special characters typical in injection syntax
SPECIAL_CHARS = set(";'\"<>()=/-*%&#\\+`!$|{}[]~^?:@")

# Regex pattern for SQL injection keywords & operators
SQL_KEYWORDS_REGEX = re.compile(
    r"\b(select|union|insert|update|delete|drop|from|where|or|and|order\s+by|group\s+by|having|benchmark|sleep|load_file|into\s+outfile|information_schema|waitfor|declare|exec)\b",
    re.IGNORECASE,
)

# Regex pattern for XSS markers, event handlers, and script elements
XSS_MARKERS_REGEX = re.compile(
    r"(<\s*script|script\s*>|on[a-z]+\s*=|javascript:|<\s*img|<\s*svg|<\s*iframe|<\s*body|<\s*details|<\s*input|alert\s*\(|prompt\s*\(|eval\s*\()",
    re.IGNORECASE,
)

# Regex pattern for quote and comment evasion characters
QUOTE_COMMENT_REGEX = re.compile(r"('|--|/\*|\*/|#|;)")


def extract_length(text: str) -> float:
    """Character length of normalized request text."""
    return float(len(text))


def extract_special_char_ratio(text: str) -> float:
    """Ratio of special syntax characters to total length."""
    if not text:
        return 0.0
    special_cnt = sum(1 for c in text if c in SPECIAL_CHARS)
    return float(special_cnt / len(text))


def extract_digit_ratio(text: str) -> float:
    """Ratio of numerical digits to total length."""
    if not text:
        return 0.0
    digit_cnt = sum(1 for c in text if c.isdigit())
    return float(digit_cnt / len(text))


def extract_shannon_entropy(text: str) -> float:
    """Shannon entropy of character frequency distribution (measures obfuscation/randomness)."""
    if not text:
        return 0.0
    n = len(text)
    counts = Counter(text)
    entropy = 0.0
    for count in counts.values():
        p = count / n
        entropy -= p * math.log2(p)
    return float(entropy)


def extract_sql_keyword_count(text: str) -> float:
    """Frequency count of SQL keywords and clauses."""
    return float(len(SQL_KEYWORDS_REGEX.findall(text)))


def extract_xss_marker_count(text: str) -> float:
    """Frequency count of HTML/JS XSS markers and event handlers."""
    return float(len(XSS_MARKERS_REGEX.findall(text)))


def extract_quote_comment_count(text: str) -> float:
    """Frequency count of quote marks, SQL comments, and delimiters."""
    return float(len(QUOTE_COMMENT_REGEX.findall(text)))


def extract_max_token_length(text: str) -> float:
    """Maximum character length of any whitespace-delimited token."""
    tokens = text.split()
    if not tokens:
        return 0.0
    return float(max(len(t) for t in tokens))


class LexicalFeatureExtractor(BaseEstimator, TransformerMixin):
    """
    Scikit-learn Transformer extracting statistical and lexical indicators
    from normalized HTTP request strings.
    """

    FEATURE_NAMES = [
        "length",
        "special_char_ratio",
        "digit_ratio",
        "shannon_entropy",
        "sql_keyword_count",
        "xss_marker_count",
        "quote_comment_count",
        "max_token_length",
    ]

    def fit(self, X: Sequence[str], y=None):
        return self

    def transform(self, X: Sequence[str]) -> np.ndarray:
        features = np.zeros((len(X), len(self.FEATURE_NAMES)), dtype=np.float64)
        for i, text in enumerate(X):
            s = str(text) if text is not None else ""
            features[i, 0] = extract_length(s)
            features[i, 1] = extract_special_char_ratio(s)
            features[i, 2] = extract_digit_ratio(s)
            features[i, 3] = extract_shannon_entropy(s)
            features[i, 4] = extract_sql_keyword_count(s)
            features[i, 5] = extract_xss_marker_count(s)
            features[i, 6] = extract_quote_comment_count(s)
            features[i, 7] = extract_max_token_length(s)
        return features

    def get_feature_names_out(self, input_features=None) -> List[str]:
        return list(self.FEATURE_NAMES)


def build_feature_union(max_tfidf_features: int = 50000) -> FeatureUnion:
    """
    Builds the composite feature extraction pipeline combining:
      1. Word-boundary character n-gram TF-IDF (n=2 to 5)
      2. Scaled dense statistical lexical indicators
    """
    tfidf = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(2, 5),
        sublinear_tf=True,
        max_features=max_tfidf_features,
    )

    lexical_pipeline = Pipeline([
        ("extractor", LexicalFeatureExtractor()),
        ("scaler", StandardScaler()),
    ])

    return FeatureUnion([
        ("tfidf", tfidf),
        ("lexical", lexical_pipeline),
    ])


def build_model_pipeline(classifier, max_tfidf_features: int = 50000) -> Pipeline:
    """
    Assembles preprocessing and classification estimator into a single pipeline.
    Ensures zero train/serve skew and unified model.joblib serialization.
    """
    return Pipeline([
        ("features", build_feature_union(max_tfidf_features=max_tfidf_features)),
        ("classifier", classifier),
    ])
