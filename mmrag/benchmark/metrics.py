from __future__ import annotations

import math

import numpy as np

from .models import (
    DetectionMetrics,
    DetectionResult,
    RetrievalGoldItem,
    RetrievalMetrics,
    VulnLabel,
)


def recall_at_k(retrieved_ids: list[str], relevant_ids: list[str], k: int) -> float:
    if not relevant_ids:
        return 0.0
    top_k = set(retrieved_ids[:k])
    relevant = set(relevant_ids)
    return len(top_k & relevant) / len(relevant)


def precision_at_k(retrieved_ids: list[str], relevant_ids: list[str], k: int) -> float:
    if k == 0:
        return 0.0
    top_k = retrieved_ids[:k]
    relevant = set(relevant_ids)
    hits = sum(1 for rid in top_k if rid in relevant)
    return hits / k


def mean_reciprocal_rank(ranked_ids: list[str], relevant_ids: list[str]) -> float:
    relevant = set(relevant_ids)
    for i, rid in enumerate(ranked_ids, 1):
        if rid in relevant:
            return 1.0 / i
    return 0.0


def ndcg_at_k(ranked_ids: list[str], relevant_ids: list[str], k: int) -> float:
    if not relevant_ids:
        return 0.0
    relevant = set(relevant_ids)

    dcg = 0.0
    for i, rid in enumerate(ranked_ids[:k], 1):
        if rid in relevant:
            dcg += 1.0 / math.log2(i + 1)

    ideal_hits = min(len(relevant), k)
    idcg = sum(1.0 / math.log2(i + 1) for i in range(1, ideal_hits + 1))

    if idcg == 0.0:
        return 0.0
    return dcg / idcg


def line_overlap_iou(predicted_lines: list[int], ground_truth_lines: list[int]) -> float:
    if not predicted_lines and not ground_truth_lines:
        return 1.0
    if not predicted_lines or not ground_truth_lines:
        return 0.0
    pred_set = set(predicted_lines)
    gt_set = set(ground_truth_lines)
    intersection = len(pred_set & gt_set)
    union = len(pred_set | gt_set)
    return intersection / union if union > 0 else 0.0


def compute_retrieval_metrics(
    gold_items: list[RetrievalGoldItem],
    retrieved_per_query: dict[str, list[str]],
    k_values: list[int] | None = None,
) -> RetrievalMetrics:
    if k_values is None:
        k_values = [1, 3, 5, 10, 20]

    if not gold_items:
        return RetrievalMetrics(num_queries=0)

    recall_sums: dict[int, float] = {k: 0.0 for k in k_values}
    precision_sums: dict[int, float] = {k: 0.0 for k in k_values}
    ndcg_sums: dict[int, float] = {k: 0.0 for k in k_values}
    mrr_sum = 0.0

    for item in gold_items:
        retrieved = retrieved_per_query.get(item.sample_id, [])
        for k in k_values:
            recall_sums[k] += recall_at_k(retrieved, item.relevant_chunk_ids, k)
            precision_sums[k] += precision_at_k(retrieved, item.relevant_chunk_ids, k)
            ndcg_sums[k] += ndcg_at_k(retrieved, item.relevant_chunk_ids, k)
        mrr_sum += mean_reciprocal_rank(retrieved, item.relevant_chunk_ids)

    n = len(gold_items)
    return RetrievalMetrics(
        recall_at_k={k: recall_sums[k] / n for k in k_values},
        precision_at_k={k: precision_sums[k] / n for k in k_values},
        mrr=mrr_sum / n,
        ndcg_at_k={k: ndcg_sums[k] / n for k in k_values},
        num_queries=n,
    )


def compute_detection_metrics(results: list[DetectionResult]) -> DetectionMetrics:
    if not results:
        return DetectionMetrics()

    tp = fp = tn = fn = 0
    per_cwe_counts: dict[str, dict[str, int]] = {}

    for r in results:
        is_positive = r.true_label == VulnLabel.VULNERABLE
        predicted_positive = r.predicted_label == VulnLabel.VULNERABLE

        if is_positive and predicted_positive:
            tp += 1
        elif not is_positive and predicted_positive:
            fp += 1
        elif not is_positive and not predicted_positive:
            tn += 1
        else:
            fn += 1

        cwe = r.true_cwe or "unknown"
        if cwe not in per_cwe_counts:
            per_cwe_counts[cwe] = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
        if is_positive and predicted_positive:
            per_cwe_counts[cwe]["tp"] += 1
        elif not is_positive and predicted_positive:
            per_cwe_counts[cwe]["fp"] += 1
        elif not is_positive and not predicted_positive:
            per_cwe_counts[cwe]["tn"] += 1
        else:
            per_cwe_counts[cwe]["fn"] += 1

    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total if total > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    per_cwe: dict[str, dict[str, float]] = {}
    for cwe, counts in per_cwe_counts.items():
        c_tp, c_fp, c_fn = counts["tp"], counts["fp"], counts["fn"]
        c_prec = c_tp / (c_tp + c_fp) if (c_tp + c_fp) > 0 else 0.0
        c_rec = c_tp / (c_tp + c_fn) if (c_tp + c_fn) > 0 else 0.0
        c_f1 = 2 * c_prec * c_rec / (c_prec + c_rec) if (c_prec + c_rec) > 0 else 0.0
        per_cwe[cwe] = {"precision": c_prec, "recall": c_rec, "f1": c_f1}

    return DetectionMetrics(
        accuracy=accuracy,
        precision=precision,
        recall=recall,
        f1=f1,
        total_samples=total,
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        per_cwe=per_cwe,
        results=results,
    )
