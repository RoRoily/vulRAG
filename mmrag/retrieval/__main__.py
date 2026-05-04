from __future__ import annotations

import argparse
import json
import sys

from mmrag.parsing.ast_parser import parse_file, collect_errors
from mmrag.parsing.cfg_builder import build_cfg
from mmrag.parsing.chunker import chunk_file
from mmrag.parsing.models import ParseResult
from .models import MetadataFilter, RetrievalConfig
from .retriever import Retriever


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="mmrag.retrieval",
        description="MM-RAG retrieval layer",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_index = subparsers.add_parser("index", help="Parse and index a C/C++ file")
    p_index.add_argument("file", help="C/C++ source file to parse and index")
    p_index.add_argument("--language", choices=["c", "cpp"], default=None)
    p_index.add_argument("--model-path", default="", help="Local path to embedding model")
    p_index.add_argument("--bm25-path", default="./mmrag_bm25.pkl")

    p_query = subparsers.add_parser("query", help="Query the index")
    p_query.add_argument("text", help="Query text (code snippet or description)")
    p_query.add_argument("--top-k", type=int, default=10)
    p_query.add_argument("--mode", choices=["fused", "bm25", "embedding"], default="fused")
    p_query.add_argument("--filter-func", default=None)
    p_query.add_argument("--filter-file", default=None)
    p_query.add_argument("--filter-kind", default=None)
    p_query.add_argument("--model-path", default="")
    p_query.add_argument("--bm25-path", default="./mmrag_bm25.pkl")

    p_stats = subparsers.add_parser("stats", help="Show index statistics")
    p_stats.add_argument("--bm25-path", default="./mmrag_bm25.pkl")

    args = parser.parse_args(argv)

    if args.command == "index":
        _cmd_index(args)
    elif args.command == "query":
        _cmd_query(args)
    elif args.command == "stats":
        _cmd_stats(args)


def _cmd_index(args) -> None:
    root, functions, source = parse_file(args.file, args.language)
    errors = collect_errors(root)
    chunks = chunk_file(functions, source, args.file)

    config = RetrievalConfig(
        model_path=args.model_path,
        bm25_path=args.bm25_path,
    )
    retriever = Retriever(config)
    stats = retriever.index(chunks)
    retriever.save()

    print(f"Indexed {stats.chunk_count} chunks from {args.file}")
    print(f"  BM25: {stats.bm25_path}")
    if stats.embedding_indexed:
        print(f"  Embedding: {stats.embedding_path}")
    else:
        print("  Embedding: skipped (no --model-path)")
    if errors:
        print(f"  Parse errors: {len(errors)}")


def _cmd_query(args) -> None:
    config = RetrievalConfig(
        model_path=args.model_path,
        bm25_path=args.bm25_path,
    )
    retriever = Retriever.load(config)

    filters = None
    if args.filter_func or args.filter_file or args.filter_kind:
        filters = MetadataFilter(
            function_names=[args.filter_func] if args.filter_func else None,
            file_paths=[args.filter_file] if args.filter_file else None,
            kinds=[args.filter_kind] if args.filter_kind else None,
        )

    if args.mode == "bm25":
        results = retriever.query_bm25_only(args.text, top_k=args.top_k, filters=filters)
    elif args.mode == "embedding":
        results = retriever.query_embedding_only(args.text, top_k=args.top_k, filters=filters)
    else:
        results = retriever.query(args.text, top_k=args.top_k, filters=filters)

    if not results:
        print("No results found.")
        return

    for r in results:
        preview = r.chunk.text.strip().split("\n")[0][:80]
        print(f"  #{r.rank} [{r.source.value}] score={r.score:.4f} {r.chunk_id}")
        print(f"       {preview}")
        print()


def _cmd_stats(args) -> None:
    config = RetrievalConfig(
        bm25_path=args.bm25_path,
    )
    retriever = Retriever.load(config)
    stats = retriever.stats()
    print(f"Chunks: {stats.chunk_count}")
    print(f"BM25 indexed: {stats.bm25_indexed}")
    print(f"Embedding indexed: {stats.embedding_indexed}")
    print(f"BM25 path: {stats.bm25_path}")


if __name__ == "__main__":
    main()
