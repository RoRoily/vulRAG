from __future__ import annotations

import argparse
import json
import sys

from .dataset import load_dataset, load_juliet_dir, save_jsonl
from .evaluator import BenchmarkEvaluator
from .models import BenchmarkReport, RetrievalGoldItem


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="mmrag.benchmark",
        description="MM-RAG evaluation benchmark framework",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_eval = subparsers.add_parser("evaluate", help="Run evaluation benchmark")
    p_eval.add_argument("--dataset", required=True, help="Path to JSONL dataset or Juliet directory")
    p_eval.add_argument("--format", choices=["auto", "jsonl", "juliet"], default="auto")
    p_eval.add_argument("--mode", choices=["retrieval", "detection", "all"], default="all")
    p_eval.add_argument("--model-path", default="", help="Embedding model path")
    p_eval.add_argument("--llm-path", default="", help="GGUF LLM path (for detection mode)")
    p_eval.add_argument("--bm25-path", default="./mmrag_bm25.pkl")
    p_eval.add_argument("--top-k", type=int, nargs="+", default=[1, 3, 5, 10, 20])
    p_eval.add_argument("--output", choices=["json", "text"], default="text")
    p_eval.add_argument("--output-file", default=None, help="Save report to file")

    p_convert = subparsers.add_parser("convert", help="Convert dataset to JSONL format")
    p_convert.add_argument("--input", required=True, help="Input directory (Juliet)")
    p_convert.add_argument("--output", required=True, help="Output JSONL path")
    p_convert.add_argument("--format", choices=["juliet"], default="juliet")
    p_convert.add_argument("--cwe-filter", nargs="+", default=None)

    args = parser.parse_args(argv)

    if args.command == "evaluate":
        _cmd_evaluate(args)
    elif args.command == "convert":
        _cmd_convert(args)


def _cmd_evaluate(args) -> None:
    samples = load_dataset(args.dataset, format=args.format)
    if not samples:
        print("No samples loaded.")
        return

    retriever = None
    analyzer = None

    if args.mode in ("retrieval", "all"):
        from mmrag.retrieval.models import RetrievalConfig
        from mmrag.retrieval.retriever import Retriever
        from mmrag.parsing.ast_parser import parse_source
        from mmrag.parsing.chunker import chunk_file

        config = RetrievalConfig(
            model_path=args.model_path,
            bm25_path=args.bm25_path,
        )

        all_chunks = []
        for sample in samples:
            source = sample.source_code
            if not source and sample.file_path:
                try:
                    from pathlib import Path
                    source = Path(sample.file_path).read_text(encoding="utf-8")
                except OSError:
                    continue
            if not source:
                continue
            try:
                source_bytes = source.encode("utf-8")
                _, functions = parse_source(source_bytes, sample.language)
                chunks = chunk_file(functions, source_bytes, sample.file_path or sample.sample_id)
                all_chunks.extend(chunks)
            except Exception:
                continue

        if all_chunks:
            retriever = Retriever(config)
            retriever.index(all_chunks)

    if args.mode in ("detection", "all") and args.llm_path:
        from mmrag.reasoning.models import LLMConfig
        from mmrag.reasoning.orchestrator import VulnerabilityAnalyzer

        llm_config = LLMConfig(model_path=args.llm_path)
        analyzer = VulnerabilityAnalyzer(llm_config=llm_config)

    evaluator = BenchmarkEvaluator(
        dataset=samples,
        retriever=retriever,
        analyzer=analyzer,
    )

    report = evaluator.evaluate_all(k_values=args.top_k)
    report.dataset_name = args.dataset

    if args.output == "json":
        output = report.model_dump_json(indent=2)
    else:
        output = _format_report_text(report)

    print(output)

    if args.output_file:
        from pathlib import Path
        Path(args.output_file).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output_file).write_text(output, encoding="utf-8")
        print(f"\nReport saved to {args.output_file}")


def _cmd_convert(args) -> None:
    if args.format == "juliet":
        samples = load_juliet_dir(args.input, cwe_filter=args.cwe_filter)
    else:
        print(f"Unknown format: {args.format}")
        return

    save_jsonl(samples, args.output)
    print(f"Converted {len(samples)} samples to {args.output}")


def _format_report_text(report: BenchmarkReport) -> str:
    lines = [
        f"Benchmark Report: {report.dataset_name}",
        f"Samples: {report.num_samples}",
        "",
    ]

    if report.retrieval_metrics and report.retrieval_metrics.num_queries > 0:
        rm = report.retrieval_metrics
        lines.append("=== Retrieval Metrics ===")
        lines.append(f"  Queries: {rm.num_queries}")
        lines.append(f"  MRR: {rm.mrr:.4f}")
        for k, v in sorted(rm.recall_at_k.items()):
            lines.append(f"  Recall@{k}: {v:.4f}")
        for k, v in sorted(rm.precision_at_k.items()):
            lines.append(f"  Precision@{k}: {v:.4f}")
        for k, v in sorted(rm.ndcg_at_k.items()):
            lines.append(f"  NDCG@{k}: {v:.4f}")
        lines.append("")

    if report.detection_metrics and report.detection_metrics.total_samples > 0:
        dm = report.detection_metrics
        lines.append("=== Detection Metrics ===")
        lines.append(f"  Total: {dm.total_samples}")
        lines.append(f"  Accuracy: {dm.accuracy:.4f}")
        lines.append(f"  Precision: {dm.precision:.4f}")
        lines.append(f"  Recall: {dm.recall:.4f}")
        lines.append(f"  F1: {dm.f1:.4f}")
        lines.append(f"  TP={dm.true_positives} FP={dm.false_positives} TN={dm.true_negatives} FN={dm.false_negatives}")
        if dm.per_cwe:
            lines.append("  Per-CWE:")
            for cwe, metrics in sorted(dm.per_cwe.items()):
                lines.append(
                    f"    {cwe}: P={metrics['precision']:.3f} R={metrics['recall']:.3f} F1={metrics['f1']:.3f}"
                )
        lines.append("")

    return "\n".join(lines)


if __name__ == "__main__":
    main()
