"""
Evaluation and benchmarking utilities for AI WAF models.
Computes Precision, Recall, F1, ROC-AUC, FPR, confusion matrices,
and single-request inference latency percentiles (p50/p95).
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Tuple

import numpy as np
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)


def evaluate_predictions(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_prob: np.ndarray | None = None,
) -> Dict[str, Any]:
    """Calculate classification performance metrics including malicious-class F1 and FPR."""
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    # cm layout: [[TN, FP], [FN, TP]]
    tn, fp, fn, tp = cm.ravel()

    precision = precision_score(y_true, y_pred, pos_label=1, zero_division=0)
    recall = recall_score(y_true, y_pred, pos_label=1, zero_division=0)
    f1_malicious = f1_score(y_true, y_pred, pos_label=1, zero_division=0)
    f1_macro = f1_score(y_true, y_pred, average="macro", zero_division=0)

    # False Positive Rate: FP / (FP + TN)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    roc_auc = 0.0
    if y_prob is not None and len(np.unique(y_true)) > 1:
        try:
            roc_auc = float(roc_auc_score(y_true, y_prob))
        except Exception:
            roc_auc = 0.0

    return {
        "precision": float(round(precision, 4)),
        "recall": float(round(recall, 4)),
        "f1_malicious": float(round(f1_malicious, 4)),
        "f1_macro": float(round(f1_macro, 4)),
        "fpr": float(round(fpr, 4)),
        "roc_auc": float(round(roc_auc, 4)),
        "confusion_matrix": {
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp),
        },
    }


def calibrate_threshold(
    y_true: np.ndarray,
    y_prob: np.ndarray,
    target_fpr: float = 0.01,
) -> Tuple[float, Dict[str, Any]]:
    """
    Calibrate decision threshold on validation set to achieve target FPR <= target_fpr.
    Returns (calibrated_threshold, metrics_at_threshold).
    """
    candidate_thresholds = np.linspace(0.10, 0.99, 90)
    best_threshold = 0.50
    best_f1 = -1.0
    best_metrics: Dict[str, Any] = {}

    # Find thresholds meeting target FPR
    valid_candidates = []

    for t in candidate_thresholds:
        y_pred = (y_prob >= t).astype(int)
        metrics = evaluate_predictions(y_true, y_pred, y_prob)

        if metrics["fpr"] <= target_fpr:
            valid_candidates.append((t, metrics))

    if valid_candidates:
        # Among candidates satisfying FPR <= target_fpr, maximize malicious F1
        valid_candidates.sort(key=lambda x: (x[1]["f1_malicious"], -x[0]), reverse=True)
        best_threshold, best_metrics = valid_candidates[0]
    else:
        # If none strictly <= target_fpr, select threshold minimizing FPR
        all_candidates = []
        for t in candidate_thresholds:
            y_pred = (y_prob >= t).astype(int)
            all_candidates.append((t, evaluate_predictions(y_true, y_pred, y_prob)))
        all_candidates.sort(key=lambda x: (x[1]["fpr"], -x[1]["f1_malicious"]))
        best_threshold, best_metrics = all_candidates[0]

    return float(round(best_threshold, 3)), best_metrics


def measure_single_request_latency(
    model_pipeline,
    sample_texts: List[str],
    n_iterations: int = 1000,
) -> Tuple[float, float]:
    """
    Measure p50 and p95 latency (in milliseconds) for individual, single-request predictions.
    Includes feature extraction, TF-IDF vectorization, and inference.
    """
    # Warmup
    for s in sample_texts[:10]:
        model_pipeline.predict_proba([s])

    latencies_ms: List[float] = []
    num_samples = len(sample_texts)

    for i in range(n_iterations):
        sample = sample_texts[i % num_samples]
        t0 = time.perf_counter()
        model_pipeline.predict_proba([sample])
        elapsed = (time.perf_counter() - t0) * 1000.0
        latencies_ms.append(elapsed)

    p50 = float(np.percentile(latencies_ms, 50))
    p95 = float(np.percentile(latencies_ms, 95))
    return round(p50, 3), round(p95, 3)
