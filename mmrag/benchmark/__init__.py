from __future__ import annotations

from .models import (
    AffectedLine,
    BenchmarkReport,
    BenchmarkSample,
    DetectionMetrics,
    DetectionResult,
    RetrievalGoldItem,
    RetrievalMetrics,
    VulnLabel,
)
from .dataset import load_dataset, load_jsonl, load_juliet_dir, save_jsonl
from .metrics import (
    compute_detection_metrics,
    compute_retrieval_metrics,
    line_overlap_iou,
    mean_reciprocal_rank,
    ndcg_at_k,
    precision_at_k,
    recall_at_k,
)
from .evaluator import BenchmarkEvaluator

__all__ = [
    "AffectedLine",
    "BenchmarkEvaluator",
    "BenchmarkReport",
    "BenchmarkSample",
    "DetectionMetrics",
    "DetectionResult",
    "RetrievalGoldItem",
    "RetrievalMetrics",
    "VulnLabel",
    "compute_detection_metrics",
    "compute_retrieval_metrics",
    "line_overlap_iou",
    "load_dataset",
    "load_jsonl",
    "load_juliet_dir",
    "mean_reciprocal_rank",
    "ndcg_at_k",
    "precision_at_k",
    "recall_at_k",
    "save_jsonl",
]
