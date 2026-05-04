from __future__ import annotations

import json
import logging
from pathlib import Path

import numpy as np

from mmrag.benchmark.models import BenchmarkSample, VulnLabel
from mmrag.parsing.ast_parser import parse_source
from mmrag.parsing.chunker import chunk_file
from mmrag.parsing.models import Chunk

from .models import Triplet

logger = logging.getLogger(__name__)

_CWE_DESCRIPTIONS: dict[str, str] = {
    "CWE-122": "Heap-based buffer overflow due to writing beyond allocated buffer boundaries",
    "CWE-121": "Stack-based buffer overflow from writing past stack buffer limits",
    "CWE-78": "OS command injection via unsanitized external input passed to system commands",
    "CWE-134": "Format string vulnerability from externally-controlled format argument",
    "CWE-190": "Integer overflow or wraparound leading to unexpected small allocation",
    "CWE-416": "Use after free where memory is accessed after being deallocated",
    "CWE-476": "NULL pointer dereference from using pointer without null check",
    "CWE-401": "Memory leak from missing free on allocated heap memory",
    "CWE-119": "Buffer overflow from improper restriction of operations within memory bounds",
    "CWE-120": "Classic buffer overflow from copying data without checking size",
}


def generate_triplets_from_benchmark(
    samples: list[BenchmarkSample],
    num_hard_negatives: int = 3,
    seed: int = 42,
) -> list[Triplet]:
    rng = np.random.RandomState(seed)

    vuln_samples = [s for s in samples if s.label == VulnLabel.VULNERABLE]
    safe_samples = [s for s in samples if s.label == VulnLabel.SAFE]

    if not vuln_samples or not safe_samples:
        logger.warning("Need both vulnerable and safe samples to generate triplets")
        return []

    vuln_chunks = _parse_samples_to_chunks(vuln_samples)
    safe_chunks = _parse_samples_to_chunks(safe_samples)

    if not vuln_chunks or not safe_chunks:
        logger.warning("Failed to parse samples into chunks")
        return []

    safe_sample_by_id = {s.sample_id: s for s in safe_samples}
    safe_chunk_list = [
        (safe_sample_by_id[sample_id], chunk)
        for sample_id, chunks in safe_chunks.items()
        for chunk in chunks
    ]

    triplets: list[Triplet] = []

    for sample in vuln_samples:
        sample_chunks = vuln_chunks.get(sample.sample_id, [])
        if not sample_chunks:
            continue

        anchor_text = _build_anchor_text(sample)

        for pos_chunk in sample_chunks:
            negatives = _find_hard_negatives(
                sample, pos_chunk, safe_chunk_list, num_hard_negatives, rng
            )
            for neg_chunk in negatives:
                triplets.append(Triplet(
                    anchor=anchor_text,
                    positive=pos_chunk.text,
                    negative=neg_chunk.text,
                    anchor_id=sample.sample_id,
                    positive_id=pos_chunk.chunk_id,
                    negative_id=neg_chunk.chunk_id,
                ))

    code_triplets = _generate_code_to_code_triplets(
        vuln_samples, vuln_chunks, safe_chunk_list, rng
    )
    triplets.extend(code_triplets)

    rng.shuffle(triplets)
    logger.info("Generated %d triplets from %d samples", len(triplets), len(samples))
    return triplets


def _build_anchor_text(sample: BenchmarkSample) -> str:
    parts: list[str] = []

    if sample.cwe_id:
        cwe_desc = _CWE_DESCRIPTIONS.get(sample.cwe_id, "")
        if cwe_desc:
            parts.append(f"{sample.cwe_id}: {cwe_desc}")
        else:
            parts.append(sample.cwe_id)
        if sample.cwe_name:
            parts.append(sample.cwe_name)

    if sample.description:
        parts.append(sample.description)

    if not parts:
        parts.append("Potential security vulnerability in C/C++ code")

    return ". ".join(parts)


def _find_hard_negatives(
    positive_sample: BenchmarkSample,
    positive_chunk: Chunk,
    safe_chunk_list: list[tuple[BenchmarkSample, Chunk]],
    n: int,
    rng: np.random.RandomState,
) -> list[Chunk]:
    if not safe_chunk_list:
        return []

    same_cwe: list[Chunk] = []
    similar_structure: list[Chunk] = []
    others: list[Chunk] = []

    pos_ast_types = set(positive_chunk.ast_node_types)

    for safe_sample, safe_chunk in safe_chunk_list:
        if positive_sample.cwe_id and safe_sample.cwe_id == positive_sample.cwe_id:
            same_cwe.append(safe_chunk)
        elif pos_ast_types and set(safe_chunk.ast_node_types) & pos_ast_types:
            similar_structure.append(safe_chunk)
        else:
            others.append(safe_chunk)

    result: list[Chunk] = []

    for pool in [same_cwe, similar_structure, others]:
        if len(result) >= n:
            break
        remaining = n - len(result)
        if len(pool) <= remaining:
            result.extend(pool)
        else:
            indices = rng.choice(len(pool), size=remaining, replace=False)
            result.extend(pool[i] for i in indices)

    return result[:n]


def _generate_code_to_code_triplets(
    vuln_samples: list[BenchmarkSample],
    vuln_chunks: dict[str, list[Chunk]],
    safe_chunk_list: list[tuple[BenchmarkSample, Chunk]],
    rng: np.random.RandomState,
) -> list[Triplet]:
    triplets: list[Triplet] = []

    by_cwe: dict[str, list[tuple[BenchmarkSample, Chunk]]] = {}
    for sample in vuln_samples:
        cwe = sample.cwe_id or "unknown"
        for chunk in vuln_chunks.get(sample.sample_id, []):
            by_cwe.setdefault(cwe, []).append((sample, chunk))

    for cwe, cwe_items in by_cwe.items():
        if len(cwe_items) < 2:
            continue
        for i, (sample_a, chunk_a) in enumerate(cwe_items):
            other_indices = [j for j in range(len(cwe_items)) if j != i]
            if not other_indices:
                continue
            pos_idx = rng.choice(other_indices)
            _, chunk_pos = cwe_items[pos_idx]

            neg_candidates = [c for s, c in safe_chunk_list]
            if not neg_candidates:
                continue
            neg_idx = rng.randint(0, len(neg_candidates))
            chunk_neg = neg_candidates[neg_idx]

            triplets.append(Triplet(
                anchor=chunk_a.text,
                positive=chunk_pos.text,
                negative=chunk_neg.text,
                anchor_id=chunk_a.chunk_id,
                positive_id=chunk_pos.chunk_id,
                negative_id=chunk_neg.chunk_id,
            ))

    return triplets


def _parse_samples_to_chunks(
    samples: list[BenchmarkSample],
) -> dict[str, list[Chunk]]:
    result: dict[str, list[Chunk]] = {}

    for sample in samples:
        source_code = sample.source_code
        if not source_code and sample.file_path:
            try:
                source_code = Path(sample.file_path).read_text(encoding="utf-8")
            except OSError:
                continue
        if not source_code:
            continue

        try:
            source_bytes = source_code.encode("utf-8")
            _, functions = parse_source(source_bytes, sample.language)
            chunks = chunk_file(
                functions, source_bytes, sample.file_path or sample.sample_id
            )
            if sample.function_name:
                chunks = [
                    c for c in chunks
                    if c.function_name == sample.function_name
                ]
            if chunks:
                result[sample.sample_id] = chunks
        except Exception as e:
            logger.warning("Failed to parse sample %s: %s", sample.sample_id, e)

    return result


def save_triplets(triplets: list[Triplet], path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for t in triplets:
            f.write(t.model_dump_json() + "\n")


def load_triplets(path: str | Path) -> list[Triplet]:
    path = Path(path)
    triplets: list[Triplet] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            data = json.loads(line)
            triplets.append(Triplet.model_validate(data))
    return triplets
