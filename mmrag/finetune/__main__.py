from __future__ import annotations

import argparse
import json
import sys

from .models import FinetuneConfig, Triplet
from .triplet_gen import generate_triplets_from_benchmark, load_triplets, save_triplets


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="mmrag.finetune",
        description="MM-RAG embedding model fine-tuning",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_gen = subparsers.add_parser("generate-triplets", help="Generate training triplets")
    p_gen.add_argument("--dataset", required=True, help="Benchmark dataset JSONL")
    p_gen.add_argument("--output", required=True, help="Output triplets JSONL")
    p_gen.add_argument("--num-hard-negatives", type=int, default=3)
    p_gen.add_argument("--seed", type=int, default=42)

    p_train = subparsers.add_parser("train", help="Fine-tune embedding model")
    p_train.add_argument("--triplets", required=True, help="Training triplets JSONL")
    p_train.add_argument("--base-model", required=True, help="Local path to base model")
    p_train.add_argument("--output-dir", default="./finetuned_model")
    p_train.add_argument("--epochs", type=int, default=3)
    p_train.add_argument("--batch-size", type=int, default=16)
    p_train.add_argument("--learning-rate", type=float, default=2e-5)
    p_train.add_argument("--eval-split", type=float, default=0.1)
    p_train.add_argument("--fp16", action="store_true", default=True)
    p_train.add_argument("--no-fp16", action="store_false", dest="fp16")
    p_train.add_argument("--gradient-checkpointing", action="store_true", default=False,
                           help="Enable gradient checkpointing to reduce VRAM usage")
    p_train.add_argument("--seed", type=int, default=42)
    p_train.add_argument("--device", default="auto")

    p_compare = subparsers.add_parser("compare", help="Compare base vs fine-tuned model")
    p_compare.add_argument("--base-model", required=True)
    p_compare.add_argument("--finetuned", required=True)
    p_compare.add_argument("--dataset", required=True)
    p_compare.add_argument("--top-k", type=int, nargs="+", default=[1, 3, 5, 10, 20])
    p_compare.add_argument("--output", choices=["json", "text"], default="text")

    args = parser.parse_args(argv)

    if args.command == "generate-triplets":
        _cmd_generate_triplets(args)
    elif args.command == "train":
        _cmd_train(args)
    elif args.command == "compare":
        _cmd_compare(args)


def _cmd_generate_triplets(args) -> None:
    from mmrag.benchmark.dataset import load_jsonl

    samples = load_jsonl(args.dataset)
    if not samples:
        print("No samples loaded.")
        return

    triplets = generate_triplets_from_benchmark(
        samples,
        num_hard_negatives=args.num_hard_negatives,
        seed=args.seed,
    )

    save_triplets(triplets, args.output)
    print(f"Generated {len(triplets)} triplets -> {args.output}")


def _cmd_train(args) -> None:
    from .trainer import EmbeddingFinetuner

    triplets = load_triplets(args.triplets)
    if not triplets:
        print("No triplets loaded.")
        return

    config = FinetuneConfig(
        base_model_path=args.base_model,
        output_dir=args.output_dir,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.learning_rate,
        eval_split=args.eval_split,
        fp16=args.fp16,
        gradient_checkpointing=args.gradient_checkpointing,
        seed=args.seed,
        device=args.device,
    )

    eval_triplets = None
    if config.eval_split > 0 and len(triplets) > 10:
        split_idx = max(1, int(len(triplets) * (1 - config.eval_split)))
        eval_triplets = triplets[split_idx:]
        triplets = triplets[:split_idx]
        print(f"Train: {len(triplets)} triplets, Eval: {len(eval_triplets)} triplets")

    finetuner = EmbeddingFinetuner(config)
    result = finetuner.train(triplets, eval_triplets=eval_triplets)

    print(f"\nTraining complete!")
    print(f"  Output: {result.output_dir}")
    print(f"  Triplets: {result.num_triplets}")
    print(f"  Epochs: {result.epochs_completed}")
    if result.eval_metrics:
        for k, v in result.eval_metrics.items():
            print(f"  {k}: {v:.4f}")


def _cmd_compare(args) -> None:
    from mmrag.benchmark.dataset import load_jsonl
    from mmrag.benchmark.metrics import compute_retrieval_metrics
    from mmrag.benchmark.models import RetrievalGoldItem
    from mmrag.parsing.ast_parser import parse_source
    from mmrag.parsing.chunker import chunk_file
    from mmrag.retrieval.models import RetrievalConfig
    from mmrag.retrieval.retriever import Retriever

    samples = load_jsonl(args.dataset)
    if not samples:
        print("No samples loaded.")
        return

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
            chunks = chunk_file(
                functions, source_bytes, sample.file_path or sample.sample_id
            )
            all_chunks.extend(chunks)
        except Exception:
            continue

    if not all_chunks:
        print("No chunks generated from dataset.")
        return

    vuln_samples = [s for s in samples if s.label.value == "vulnerable"]
    gold_items = []
    for sample in vuln_samples:
        relevant_ids = [
            c.chunk_id for c in all_chunks
            if c.function_name == sample.function_name
        ]
        if relevant_ids:
            query = sample.description or f"{sample.cwe_id} vulnerability"
            gold_items.append(RetrievalGoldItem(
                query=query,
                relevant_chunk_ids=relevant_ids,
                sample_id=sample.sample_id,
            ))

    if not gold_items:
        print("No gold items for evaluation.")
        return

    results: dict[str, dict[str, list[str]]] = {}

    for label, model_path in [("base", args.base_model), ("finetuned", args.finetuned)]:
        config = RetrievalConfig(model_path=model_path, device="auto")
        retriever = Retriever(config)
        retriever.index(all_chunks)

        max_k = max(args.top_k)
        retrieved_per_query: dict[str, list[str]] = {}
        for item in gold_items:
            query_results = retriever.query(item.query, top_k=max_k)
            retrieved_per_query[item.sample_id] = [r.chunk_id for r in query_results]

        results[label] = retrieved_per_query

    print("\n=== Model Comparison ===\n")
    print(f"{'Metric':<20} {'Base':<12} {'Finetuned':<12} {'Delta':<12}")
    print("-" * 56)

    for label in ["base", "finetuned"]:
        metrics = compute_retrieval_metrics(gold_items, results[label], args.top_k)
        if label == "base":
            base_metrics = metrics
        else:
            ft_metrics = metrics

    print(f"{'MRR':<20} {base_metrics.mrr:<12.4f} {ft_metrics.mrr:<12.4f} {ft_metrics.mrr - base_metrics.mrr:+.4f}")
    for k in args.top_k:
        b_r = base_metrics.recall_at_k.get(k, 0)
        f_r = ft_metrics.recall_at_k.get(k, 0)
        print(f"{'Recall@' + str(k):<20} {b_r:<12.4f} {f_r:<12.4f} {f_r - b_r:+.4f}")
    for k in args.top_k:
        b_n = base_metrics.ndcg_at_k.get(k, 0)
        f_n = ft_metrics.ndcg_at_k.get(k, 0)
        print(f"{'NDCG@' + str(k):<20} {b_n:<12.4f} {f_n:<12.4f} {f_n - b_n:+.4f}")


if __name__ == "__main__":
    main()
