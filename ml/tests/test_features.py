"""
Unit tests for lexical feature extraction and sklearn pipeline integration (Task 2).
"""

import math
import numpy as np
import pytest
from sklearn.linear_model import LogisticRegression

from ml.features import (
    LexicalFeatureExtractor,
    build_feature_union,
    build_model_pipeline,
    extract_digit_ratio,
    extract_length,
    extract_max_token_length,
    extract_quote_comment_count,
    extract_shannon_entropy,
    extract_special_char_ratio,
    extract_sql_keyword_count,
    extract_xss_marker_count,
)


def test_extract_length():
    assert extract_length("") == 0.0
    assert extract_length("get /products") == 13.0


def test_extract_special_char_ratio():
    clean = "get products"
    assert extract_special_char_ratio(clean) == 0.0

    sqli = "q=' or 1=1--"
    ratio = extract_special_char_ratio(sqli)
    assert ratio > 0.3


def test_extract_digit_ratio():
    no_digits = "hello world"
    assert extract_digit_ratio(no_digits) == 0.0

    digits = "id=12345"
    assert extract_digit_ratio(digits) == 5.0 / 8.0


def test_extract_shannon_entropy():
    # Repeated single character has 0 entropy
    assert extract_shannon_entropy("aaaaaa") == 0.0
    # Two equally frequent characters have entropy 1.0 (-0.5*log2(0.5)*2)
    assert pytest.approx(extract_shannon_entropy("abababab"), 0.01) == 1.0
    # Obfuscated random strings have higher entropy
    assert extract_shannon_entropy("q=a%20b%20c%20d") > 2.0


def test_extract_sql_keyword_count():
    assert extract_sql_keyword_count("get /index.html") == 0.0
    sql = "select username, password from users where id=1 or 1=1"
    # select, from, where, or: 4 keywords
    assert extract_sql_keyword_count(sql) == 4.0


def test_extract_xss_marker_count():
    assert extract_xss_marker_count("get /products?q=shoes") == 0.0
    xss = "<script>alert(1)</script>"
    # <script, script>, alert(
    assert extract_xss_marker_count(xss) >= 2.0

    event_handler = "<img src=x onerror=alert(1)>"
    assert extract_xss_marker_count(event_handler) >= 2.0


def test_extract_quote_comment_count():
    assert extract_quote_comment_count("get /items") == 0.0
    sample = "admin'-- /* comment */;"
    # ', --, /*, */, ;
    assert extract_quote_comment_count(sample) >= 4.0


def test_extract_max_token_length():
    assert extract_max_token_length("") == 0.0
    sample = "get /api/supercalifragilisticexpialidocious/search"
    # longest token is the path
    assert extract_max_token_length(sample) == len("/api/supercalifragilisticexpialidocious/search")


def test_lexical_feature_extractor_transformer():
    extractor = LexicalFeatureExtractor()
    samples = [
        "get /products",
        "get /search q=' or 1=1--",
        "post /comment text=<script>alert(1)</script>",
    ]
    features = extractor.fit_transform(samples)
    assert isinstance(features, np.ndarray)
    assert features.shape == (3, 8)
    assert len(extractor.get_feature_names_out()) == 8


def test_full_pipeline_fit_and_predict():
    samples = [
        "get /products?category=books",
        "get /cart/view",
        "get /search?q=' or 1=1--",
        "post /comment body=<script>alert(1)</script>",
    ]
    labels = [0, 0, 1, 1]

    pipeline = build_model_pipeline(
        classifier=LogisticRegression(random_state=42),
        max_tfidf_features=1000,
    )
    pipeline.fit(samples, labels)
    preds = pipeline.predict(samples)
    assert len(preds) == 4
    # Check probability predictions work
    probs = pipeline.predict_proba(samples)
    assert probs.shape == (4, 2)
