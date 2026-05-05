from __future__ import annotations

import argparse
import json
import sys

from .ast_parser import collect_errors, parse_file
from .cfg_builder import build_cfg
from .chunker import chunk_file
from .models import ParseResult, SliceCriterion, SliceDirection
from .slicer import compute_slice


def _parse_slice_arg(s: str) -> SliceCriterion:
    parts = s.split(":", 1)
    line = int(parts[0])
    variable = parts[1] if len(parts) > 1 else None
    return SliceCriterion(line=line, variable=variable)


def _text_output(result: ParseResult, slices: list | None = None) -> str:
    lines: list[str] = []
    lines.append(f"File: {result.file_path} ({result.language})")
    lines.append(f"Functions: {len(result.functions)}")
    lines.append("")

    for func in result.functions:
        sr = func.source_range
        lines.append(f"  {func.name}() [{sr.start.line}-{sr.end.line}]")
        lines.append(f"    return: {func.return_type}")
        lines.append(f"    params: {', '.join(p.name for p in func.parameters)}")
        cfg = result.cfgs.get(func.name)
        if cfg:
            lines.append(f"    CFG: {len(cfg.blocks)} blocks, {len(cfg.edges)} edges")
            if cfg.warnings:
                lines.append(f"    warnings: {len(cfg.warnings)}")
        lines.append("")

    lines.append(f"Chunks: {len(result.chunks)}")
    for chunk in result.chunks:
        sr = chunk.source_range
        lines.append(f"  [{chunk.kind.value}] {chunk.chunk_id} ({chunk.line_count} lines)")

    if result.errors:
        lines.append("")
        lines.append(f"Parse errors: {len(result.errors)}")
        for err in result.errors:
            lines.append(f"  {err}")

    if slices:
        lines.append("")
        for sl in slices:
            lines.append(f"Slice ({sl.direction.value}) on {sl.criterion}:")
            lines.append(f"  function: {sl.function_name}")
            lines.append(f"  lines: {sl.included_lines}")
            lines.append("  ---")
            lines.append(sl.source_text)
            lines.append("  ---")

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="mmrag.parsing",
        description="MM-RAG C/C++ parsing layer",
    )
    parser.add_argument("file", help="C/C++ source file to parse")
    parser.add_argument("--language", choices=["c", "cpp"], default=None)
    parser.add_argument("--output", choices=["json", "text"], default="json")
    parser.add_argument(
        "--slice", dest="slice_spec", default=None,
        help="Slice criterion as LINE or LINE:VAR (e.g. 18:result)",
    )
    parser.add_argument(
        "--direction", choices=["backward", "forward"], default="backward",
    )

    args = parser.parse_args(argv)

    root, functions, source = parse_file(args.file, args.language)
    errors = collect_errors(root)

    cfgs = {}
    for func in functions:
        cfg = build_cfg(func)
        cfgs[func.name] = cfg

    chunks = chunk_file(functions, source, args.file, cfgs=cfgs)

    result = ParseResult(
        file_path=args.file,
        language=args.language or "c",
        functions=functions,
        cfgs=cfgs,
        chunks=chunks,
        errors=errors,
    )

    slices = []
    if args.slice_spec:
        criterion = _parse_slice_arg(args.slice_spec)
        direction = SliceDirection(args.direction)
        for func_name, cfg in cfgs.items():
            sl = compute_slice(cfg, source, criterion, direction)
            if sl.included_lines:
                slices.append(sl)

    if args.output == "json":
        data = result.model_dump(mode="json")
        if slices:
            data["slices"] = [s.model_dump(mode="json") for s in slices]
        print(json.dumps(data, indent=2, ensure_ascii=False))
    else:
        print(_text_output(result, slices))


if __name__ == "__main__":
    main()
