from __future__ import annotations

from mmrag.parsing.models import Chunk, ChunkKind, SourceLocation, SourceRange
from mmrag.retrieval.fusion import reciprocal_rank_fusion
from mmrag.retrieval.models import RetrievalResult, RetrievalSource


def _make_chunk(chunk_id: str) -> Chunk:
    return Chunk(
        chunk_id=chunk_id,
        kind=ChunkKind.FUNCTION,
        file_path="test.c",
        function_name="test",
        source_range=SourceRange(
            start=SourceLocation(line=1, column=0),
            end=SourceLocation(line=10, column=0),
            start_byte=0,
            end_byte=100,
        ),
        text="void test() {}",
        line_count=10,
        ast_node_types=["function_definition"],
    )


def _make_result(chunk_id: str, rank: int, source: RetrievalSource) -> RetrievalResult:
    return RetrievalResult(
        chunk_id=chunk_id,
        chunk=_make_chunk(chunk_id),
        score=1.0 / rank,
        rank=rank,
        source=source,
    )


def test_rrf_basic():
    bm25 = [
        _make_result("A", 1, RetrievalSource.BM25),
        _make_result("B", 2, RetrievalSource.BM25),
        _make_result("C", 3, RetrievalSource.BM25),
    ]
    emb = [
        _make_result("B", 1, RetrievalSource.EMBEDDING),
        _make_result("C", 2, RetrievalSource.EMBEDDING),
        _make_result("D", 3, RetrievalSource.EMBEDDING),
    ]
    fused = reciprocal_rank_fusion(bm25, emb, top_k=10, rrf_k=60)

    assert len(fused) == 4
    assert fused[0].chunk_id == "B"
    assert all(r.source == RetrievalSource.FUSED for r in fused)
    assert fused[0].rank == 1


def test_rrf_single_source():
    bm25 = [_make_result("A", 1, RetrievalSource.BM25)]
    emb = [_make_result("B", 1, RetrievalSource.EMBEDDING)]
    fused = reciprocal_rank_fusion(bm25, emb, top_k=10, rrf_k=60)

    assert len(fused) == 2
    ids = {r.chunk_id for r in fused}
    assert ids == {"A", "B"}


def test_rrf_weights():
    bm25 = [
        _make_result("A", 1, RetrievalSource.BM25),
        _make_result("B", 2, RetrievalSource.BM25),
    ]
    emb = [
        _make_result("B", 1, RetrievalSource.EMBEDDING),
        _make_result("A", 2, RetrievalSource.EMBEDDING),
    ]
    fused_bm25_heavy = reciprocal_rank_fusion(
        bm25, emb, top_k=10, rrf_k=60, bm25_weight=10.0, embedding_weight=1.0
    )
    assert fused_bm25_heavy[0].chunk_id == "A"

    fused_emb_heavy = reciprocal_rank_fusion(
        bm25, emb, top_k=10, rrf_k=60, bm25_weight=1.0, embedding_weight=10.0
    )
    assert fused_emb_heavy[0].chunk_id == "B"


def test_rrf_top_k():
    bm25 = [_make_result(f"chunk_{i}", i, RetrievalSource.BM25) for i in range(1, 11)]
    emb = [_make_result(f"chunk_{i}", i, RetrievalSource.EMBEDDING) for i in range(1, 11)]
    fused = reciprocal_rank_fusion(bm25, emb, top_k=3, rrf_k=60)
    assert len(fused) == 3


def test_rrf_empty_inputs():
    assert reciprocal_rank_fusion([], [], top_k=10) == []

    bm25 = [_make_result("A", 1, RetrievalSource.BM25)]
    fused = reciprocal_rank_fusion(bm25, [], top_k=10)
    assert len(fused) == 1
    assert fused[0].chunk_id == "A"

    emb = [_make_result("B", 1, RetrievalSource.EMBEDDING)]
    fused = reciprocal_rank_fusion([], emb, top_k=10)
    assert len(fused) == 1
    assert fused[0].chunk_id == "B"


def test_rrf_ranks_are_sequential():
    bm25 = [_make_result(f"c{i}", i, RetrievalSource.BM25) for i in range(1, 6)]
    emb = [_make_result(f"c{i}", i, RetrievalSource.EMBEDDING) for i in range(1, 6)]
    fused = reciprocal_rank_fusion(bm25, emb, top_k=5)
    for i, r in enumerate(fused):
        assert r.rank == i + 1
