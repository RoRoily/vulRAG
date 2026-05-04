from __future__ import annotations

from mmrag.parsing.models import Chunk
from .models import RetrievalResult, RetrievalSource


def reciprocal_rank_fusion(
    bm25_results: list[RetrievalResult],
    embedding_results: list[RetrievalResult],
    top_k: int = 20,
    rrf_k: int = 60,
    bm25_weight: float = 1.0,
    embedding_weight: float = 1.0,
) -> list[RetrievalResult]:
    scores: dict[str, float] = {}
    chunks: dict[str, Chunk] = {}

    for r in bm25_results:
        scores[r.chunk_id] = scores.get(r.chunk_id, 0.0) + bm25_weight / (rrf_k + r.rank)
        chunks[r.chunk_id] = r.chunk

    for r in embedding_results:
        scores[r.chunk_id] = scores.get(r.chunk_id, 0.0) + embedding_weight / (rrf_k + r.rank)
        chunks[r.chunk_id] = r.chunk

    sorted_ids = sorted(scores.keys(), key=lambda cid: scores[cid], reverse=True)

    results: list[RetrievalResult] = []
    for rank, cid in enumerate(sorted_ids[:top_k], start=1):
        results.append(RetrievalResult(
            chunk_id=cid,
            chunk=chunks[cid],
            score=scores[cid],
            rank=rank,
            source=RetrievalSource.FUSED,
        ))
    return results
