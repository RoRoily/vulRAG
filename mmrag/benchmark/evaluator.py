from __future__ import annotations

import logging
from pathlib import Path

from mmrag.parsing.ast_parser import parse_source
from mmrag.parsing.chunker import chunk_file
from mmrag.parsing.cfg_builder import build_cfg
from mmrag.retrieval.retriever import Retriever

from .dataset import load_dataset
from .metrics import (
    compute_detection_metrics,
    compute_retrieval_metrics,
    line_overlap_iou,
)
from .models import (
    BenchmarkReport,
    BenchmarkSample,
    DetectionMetrics,
    DetectionResult,
    RetrievalGoldItem,
    RetrievalMetrics,
    VulnLabel,
)

logger = logging.getLogger(__name__)


class BenchmarkEvaluator:
    def __init__(
        self,
        dataset: list[BenchmarkSample],
        retriever: Retriever | None = None,
        analyzer=None,
    ) -> None:
        self._dataset = dataset
        self._retriever = retriever
        self._analyzer = analyzer

    def evaluate_retrieval(
        self,
        gold_items: list[RetrievalGoldItem],
        k_values: list[int] | None = None,
    ) -> RetrievalMetrics:
        if self._retriever is None:
            logger.warning("No retriever provided, skipping retrieval evaluation")
            return RetrievalMetrics(num_queries=0)

        if k_values is None:
            k_values = [1, 3, 5, 10, 20]

        retrieved_per_query: dict[str, list[str]] = {}
        max_k = max(k_values)

        for item in gold_items:
            results = self._retriever.query(item.query, top_k=max_k)
            retrieved_per_query[item.sample_id] = [r.chunk_id for r in results]

        return compute_retrieval_metrics(gold_items, retrieved_per_query, k_values)

    def evaluate_detection(
        self,
        samples: list[BenchmarkSample] | None = None,
    ) -> DetectionMetrics:
        if self._analyzer is None:
            logger.warning("No analyzer provided, skipping detection evaluation")
            return DetectionMetrics()

        if samples is None:
            samples = self._dataset

        results: list[DetectionResult] = []
        for sample in samples:
            result = self._run_single_sample(sample)
            results.append(result)

        return compute_detection_metrics(results)

    def evaluate_all(
        self,
        gold_items: list[RetrievalGoldItem] | None = None,
        k_values: list[int] | None = None,
    ) -> BenchmarkReport:
        retrieval_metrics = None
        if gold_items and self._retriever is not None:
            retrieval_metrics = self.evaluate_retrieval(gold_items, k_values)

        detection_metrics = None
        if self._analyzer is not None:
            detection_metrics = self.evaluate_detection()

        return BenchmarkReport(
            dataset_name="benchmark",
            num_samples=len(self._dataset),
            retrieval_metrics=retrieval_metrics,
            detection_metrics=detection_metrics,
        )

    def _run_single_sample(self, sample: BenchmarkSample) -> DetectionResult:
        source_code = sample.source_code
        if not source_code and sample.file_path:
            try:
                source_code = Path(sample.file_path).read_text(encoding="utf-8")
            except OSError as e:
                logger.warning("Cannot read %s: %s", sample.file_path, e)
                return DetectionResult(
                    sample_id=sample.sample_id,
                    predicted_label=VulnLabel.SAFE,
                    true_label=sample.label,
                    true_cwe=sample.cwe_id,
                    correct=(sample.label == VulnLabel.SAFE),
                )

        if not source_code:
            return DetectionResult(
                sample_id=sample.sample_id,
                predicted_label=VulnLabel.SAFE,
                true_label=sample.label,
                true_cwe=sample.cwe_id,
                correct=(sample.label == VulnLabel.SAFE),
            )

        source_bytes = source_code.encode("utf-8")
        try:
            _, functions = parse_source(source_bytes, sample.language)
        except Exception as e:
            logger.warning("Parse failed for %s: %s", sample.sample_id, e)
            return DetectionResult(
                sample_id=sample.sample_id,
                predicted_label=VulnLabel.SAFE,
                true_label=sample.label,
                true_cwe=sample.cwe_id,
                correct=(sample.label == VulnLabel.SAFE),
            )

        target_funcs = functions
        if sample.function_name:
            target_funcs = [f for f in functions if f.name == sample.function_name]
            if not target_funcs:
                target_funcs = functions

        predicted_label = VulnLabel.SAFE
        predicted_cwe: str | None = None
        confidence = 0.0
        predicted_lines: list[int] = []

        from mmrag.reasoning.models import Verdict

        for func in target_funcs:
            cfg = build_cfg(func)
            try:
                report = self._analyzer.analyze_function(
                    func, cfg, source_bytes
                )
            except Exception as e:
                logger.warning(
                    "Analysis failed for %s/%s: %s",
                    sample.sample_id, func.name, e,
                )
                continue

            if report.verdict == Verdict.VULNERABLE:
                predicted_label = VulnLabel.VULNERABLE
                predicted_cwe = report.vulnerability_type
                confidence = max(confidence, report.confidence)
                if report.source_sink_path:
                    predicted_lines.extend(
                        p.line for p in report.source_sink_path
                    )

        gt_lines = [al.line for al in sample.affected_lines]
        overlap = line_overlap_iou(predicted_lines, gt_lines)

        correct = predicted_label == sample.label
        return DetectionResult(
            sample_id=sample.sample_id,
            predicted_label=predicted_label,
            predicted_cwe=predicted_cwe,
            confidence=confidence,
            true_label=sample.label,
            true_cwe=sample.cwe_id,
            correct=correct,
            line_overlap=overlap,
        )
