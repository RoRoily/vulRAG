from __future__ import annotations

import argparse
import json

from .models import LLMConfig
from .orchestrator import VulnerabilityAnalyzer


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="mmrag.reasoning",
        description="MM-RAG reasoning layer — Actor-Critic adversarial vulnerability analysis",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_analyze = subparsers.add_parser("analyze", help="Analyze a C/C++ file for vulnerabilities")
    p_analyze.add_argument("file", help="C/C++ source file to analyze")
    p_analyze.add_argument("--model-path", required=True, help="Path to GGUF model file")
    p_analyze.add_argument("--function", default=None, help="Analyze only this function")
    p_analyze.add_argument("--n-gpu-layers", type=int, default=-1)
    p_analyze.add_argument("--n-ctx", type=int, default=16384)
    p_analyze.add_argument("--output", choices=["json", "text"], default="text")
    p_analyze.add_argument("--bm25-path", default="", help="BM25 index path for retrieval context")

    args = parser.parse_args(argv)

    if args.command == "analyze":
        _cmd_analyze(args)


def _cmd_analyze(args) -> None:
    llm_config = LLMConfig(
        model_path=args.model_path,
        n_gpu_layers=args.n_gpu_layers,
        n_ctx=args.n_ctx,
    )

    retrieval_config = None
    if args.bm25_path:
        from mmrag.retrieval.models import RetrievalConfig
        retrieval_config = RetrievalConfig(bm25_path=args.bm25_path)

    analyzer = VulnerabilityAnalyzer(llm_config, retrieval_config)

    if args.function:
        from mmrag.parsing.ast_parser import parse_file
        from mmrag.parsing.cfg_builder import build_cfg
        root, functions, source = parse_file(args.file)
        by_name = {f.name: f for f in functions}
        if args.function not in by_name:
            print(f"Function '{args.function}' not found. Available: {list(by_name.keys())}")
            return
        func = by_name[args.function]
        cfg = build_cfg(func)
        report = analyzer.analyze_function(func, cfg, source)
        reports = [report]
    else:
        reports = analyzer.analyze_file(args.file)

    if not reports:
        print("No functions with dangerous API calls found.")
        return

    if args.output == "json":
        data = [r.model_dump(mode="json") for r in reports]
        print(json.dumps(data, indent=2, ensure_ascii=False))
    else:
        for r in reports:
            _print_report(r)


def _print_report(report) -> None:
    print(f"{'='*60}")
    print(f"Function: {report.function_name}() [{report.source_range_start_line}-{report.source_range_end_line}]")
    print(f"Verdict:  {report.verdict.value} (confidence: {report.confidence:.2f})")
    if report.vulnerability_type:
        print(f"Type:     {report.vulnerability_type}")
    if report.source_sink_path:
        print(f"Source→Sink Path:")
        for p in report.source_sink_path:
            print(f"  line {p.line:4d} [{p.role.value:12s}] {p.code}")
    print(f"Time:     {report.analysis_time_seconds:.1f}s")
    dr = report.debate_record
    for rd in dr.rounds:
        print(f"\n--- Round {rd.round_number} ---")
        print(f"  Attacker: {rd.attacker_argument.vulnerability_type} "
              f"(conf={rd.attacker_argument.confidence:.2f})")
        print(f"    {rd.attacker_argument.reasoning[:120]}...")
        print(f"  Defender: {rd.defender_argument.verdict.value}")
        print(f"    {rd.defender_argument.reasoning[:120]}...")
    if dr.judge_verdict:
        print(f"\n--- Judge ---")
        print(f"  {dr.judge_verdict.summary[:200]}")
    print()


if __name__ == "__main__":
    main()
