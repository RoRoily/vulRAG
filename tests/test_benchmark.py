from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from mmrag.benchmark.models import (
    AffectedLine,
    BenchmarkReport,
    BenchmarkSample,
    DetectionMetrics,
    DetectionResult,
    RetrievalGoldItem,
    RetrievalMetrics,
    VulnLabel,
)
from mmrag.benchmark.dataset import load_jsonl, save_jsonl, load_dataset
from mmrag.benchmark.metrics import (
    compute_detection_metrics,
    compute_retrieval_metrics,
    line_overlap_iou,
    mean_reciprocal_rank,
    ndcg_at_k,
    precision_at_k,
    recall_at_k,
)
from mmrag.benchmark.evaluator import BenchmarkEvaluator


@pytest.fixture
def benchmark_jsonl() -> Path:
    return Path(__file__).parent / "fixtures" / "benchmark_sample.jsonl"


class TestModels:
    def test_benchmark_sample_roundtrip(self):
        sample = BenchmarkSample(
            sample_id="test-1",
            label=VulnLabel.VULNERABLE,
            cwe_id="CWE-122",
            source_code="void foo() { malloc(10); }",
            affected_lines=[AffectedLine(line=1, description="malloc")],
        )
        data = json.loads(sample.model_dump_json())
        restored = BenchmarkSample.model_validate(data)
        assert restored.sample_id == "test-1"
        assert restored.label == VulnLabel.VULNERABLE
        assert restored.affected_lines[0].line == 1

    def test_detection_result_correct_flag(self):
        r = DetectionResult(
            sample_id="x",
            predicted_label=VulnLabel.VULNERABLE,
            true_label=VulnLabel.VULNERABLE,
            correct=True,
        )
        assert r.correct is True

    def test_benchmark_report_json(self):
        report = BenchmarkReport(
            dataset_name="test",
            num_samples=10,
            retrieval_metrics=RetrievalMetrics(
                recall_at_k={5: 0.8}, mrr=0.6, num_queries=5
            ),
        )
        data = json.loads(report.model_dump_json())
        assert data["dataset_name"] == "test"
        assert data["retrieval_metrics"]["mrr"] == 0.6


class TestDataset:
    def test_load_jsonl(self, benchmark_jsonl):
        samples = load_jsonl(benchmark_jsonl)
        assert len(samples) == 6
        vuln = [s for s in samples if s.label == VulnLabel.VULNERABLE]
        safe = [s for s in samples if s.label == VulnLabel.SAFE]
        assert len(vuln) == 3
        assert len(safe) == 3

    def test_save_load_roundtrip(self, benchmark_jsonl):
        samples = load_jsonl(benchmark_jsonl)
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = Path(tmpdir) / "out.jsonl"
            save_jsonl(samples, out_path)
            reloaded = load_jsonl(out_path)
            assert len(reloaded) == len(samples)
            assert reloaded[0].sample_id == samples[0].sample_id

    def test_load_dataset_auto_jsonl(self, benchmark_jsonl):
        samples = load_dataset(benchmark_jsonl)
        assert len(samples) == 6

    def test_load_dataset_unknown_format(self):
        with pytest.raises(ValueError, match="Cannot auto-detect"):
            load_dataset(Path("/fake/path.xyz"))

    def test_sample_fields(self, benchmark_jsonl):
        samples = load_jsonl(benchmark_jsonl)
        vuln = next(s for s in samples if s.sample_id == "vuln-001")
        assert vuln.cwe_id == "CWE-122"
        assert vuln.function_name == "heap_overflow"
        assert len(vuln.affected_lines) == 1
        assert vuln.source_code != ""


class TestMetrics:
    def test_recall_at_k_perfect(self):
        assert recall_at_k(["a", "b", "c"], ["a", "b"], 3) == 1.0

    def test_recall_at_k_partial(self):
        assert recall_at_k(["a", "b", "c"], ["a", "d"], 3) == 0.5

    def test_recall_at_k_empty_relevant(self):
        assert recall_at_k(["a", "b"], [], 2) == 0.0

    def test_precision_at_k(self):
        assert precision_at_k(["a", "b", "c", "d"], ["a", "c"], 4) == 0.5

    def test_precision_at_k_zero(self):
        assert precision_at_k(["a", "b"], ["c", "d"], 2) == 0.0

    def test_mrr_first(self):
        assert mean_reciprocal_rank(["a", "b", "c"], ["a"]) == 1.0

    def test_mrr_second(self):
        assert mean_reciprocal_rank(["a", "b", "c"], ["b"]) == 0.5

    def test_mrr_not_found(self):
        assert mean_reciprocal_rank(["a", "b"], ["z"]) == 0.0

    def test_ndcg_at_k_perfect(self):
        score = ndcg_at_k(["a", "b"], ["a", "b"], 2)
        assert abs(score - 1.0) < 1e-6

    def test_ndcg_at_k_partial(self):
        score = ndcg_at_k(["x", "a"], ["a", "b"], 2)
        assert 0.0 < score < 1.0

    def test_ndcg_at_k_empty(self):
        assert ndcg_at_k(["a", "b"], [], 2) == 0.0

    def test_line_overlap_iou_perfect(self):
        assert line_overlap_iou([1, 2, 3], [1, 2, 3]) == 1.0

    def test_line_overlap_iou_partial(self):
        assert line_overlap_iou([1, 2, 3], [2, 3, 4]) == 0.5

    def test_line_overlap_iou_empty(self):
        assert line_overlap_iou([], []) == 1.0
        assert line_overlap_iou([1], []) == 0.0
        assert line_overlap_iou([], [1]) == 0.0

    def test_compute_retrieval_metrics(self):
        gold = [
            RetrievalGoldItem(query="q1", relevant_chunk_ids=["a", "b"], sample_id="s1"),
            RetrievalGoldItem(query="q2", relevant_chunk_ids=["c"], sample_id="s2"),
        ]
        retrieved = {
            "s1": ["a", "x", "b", "y"],
            "s2": ["y", "c", "z"],
        }
        metrics = compute_retrieval_metrics(gold, retrieved, k_values=[1, 3, 5])
        assert metrics.num_queries == 2
        assert metrics.mrr > 0
        assert metrics.recall_at_k[3] > 0

    def test_compute_detection_metrics(self):
        results = [
            DetectionResult(sample_id="1", predicted_label=VulnLabel.VULNERABLE, true_label=VulnLabel.VULNERABLE, true_cwe="CWE-122"),
            DetectionResult(sample_id="2", predicted_label=VulnLabel.SAFE, true_label=VulnLabel.SAFE, true_cwe="CWE-122"),
            DetectionResult(sample_id="3", predicted_label=VulnLabel.VULNERABLE, true_label=VulnLabel.SAFE, true_cwe="CWE-78"),
            DetectionResult(sample_id="4", predicted_label=VulnLabel.SAFE, true_label=VulnLabel.VULNERABLE, true_cwe="CWE-78"),
        ]
        metrics = compute_detection_metrics(results)
        assert metrics.total_samples == 4
        assert metrics.true_positives == 1
        assert metrics.false_positives == 1
        assert metrics.true_negatives == 1
        assert metrics.false_negatives == 1
        assert metrics.accuracy == 0.5
        assert "CWE-122" in metrics.per_cwe
        assert "CWE-78" in metrics.per_cwe

    def test_compute_detection_metrics_empty(self):
        metrics = compute_detection_metrics([])
        assert metrics.total_samples == 0


class TestEvaluator:
    def test_evaluator_no_retriever(self, benchmark_jsonl):
        samples = load_jsonl(benchmark_jsonl)
        evaluator = BenchmarkEvaluator(dataset=samples)
        gold = [RetrievalGoldItem(query="test", relevant_chunk_ids=["x"], sample_id="s1")]
        metrics = evaluator.evaluate_retrieval(gold)
        assert metrics.num_queries == 0

    def test_evaluator_no_analyzer(self, benchmark_jsonl):
        samples = load_jsonl(benchmark_jsonl)
        evaluator = BenchmarkEvaluator(dataset=samples)
        metrics = evaluator.evaluate_detection()
        assert metrics.total_samples == 0

    def test_evaluator_evaluate_all_empty(self, benchmark_jsonl):
        samples = load_jsonl(benchmark_jsonl)
        evaluator = BenchmarkEvaluator(dataset=samples)
        report = evaluator.evaluate_all()
        assert report.num_samples == 6
        assert report.retrieval_metrics is None
        assert report.detection_metrics is None
