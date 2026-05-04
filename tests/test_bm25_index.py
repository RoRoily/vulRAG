from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from mmrag.parsing.ast_parser import parse_file
from mmrag.parsing.chunker import chunk_file
from mmrag.retrieval.bm25_index import BM25Index
from mmrag.retrieval.models import MetadataFilter


@pytest.fixture
def sample_chunks():
    root, functions, source = parse_file(
        str(Path(__file__).parent / "fixtures" / "sample.c")
    )
    return chunk_file(functions, source, "tests/fixtures/sample.c")


def test_build_and_count(sample_chunks):
    index = BM25Index()
    index.build(sample_chunks)
    assert index.chunk_count == len(sample_chunks)


def test_query_returns_results(sample_chunks):
    index = BM25Index()
    index.build(sample_chunks)
    results = index.query("malloc free buffer", top_k=5)
    assert len(results) > 0
    assert results[0].rank == 1
    assert results[0].score > 0


def test_query_exact_function(sample_chunks):
    index = BM25Index()
    index.build(sample_chunks)
    results = index.query("resource_handler malloc buffer", top_k=5)
    assert len(results) > 0
    top_funcs = [r.chunk.function_name for r in results[:3]]
    assert "resource_handler" in top_funcs


def test_metadata_filter_by_function(sample_chunks):
    index = BM25Index()
    index.build(sample_chunks)
    filters = MetadataFilter(function_names=["add"])
    results = index.query("int return", top_k=10, filters=filters)
    for r in results:
        assert r.chunk.function_name == "add"


def test_metadata_filter_by_kind(sample_chunks):
    index = BM25Index()
    index.build(sample_chunks)
    filters = MetadataFilter(kinds=["function"])
    results = index.query("data processing", top_k=20, filters=filters)
    for r in results:
        assert r.chunk.kind.value == "function"


def test_persistence_roundtrip(sample_chunks):
    index = BM25Index()
    index.build(sample_chunks)

    with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
        path = f.name

    try:
        index.save(path)
        loaded = BM25Index.load(path)
        assert loaded.chunk_count == index.chunk_count

        results_orig = index.query("malloc buffer", top_k=5)
        results_loaded = loaded.query("malloc buffer", top_k=5)
        assert len(results_orig) == len(results_loaded)
        assert [r.chunk_id for r in results_orig] == [r.chunk_id for r in results_loaded]
    finally:
        Path(path).unlink(missing_ok=True)


def test_empty_query(sample_chunks):
    index = BM25Index()
    index.build(sample_chunks)
    results = index.query("", top_k=5)
    assert results == []


def test_empty_index():
    index = BM25Index()
    index.build([])
    results = index.query("anything", top_k=5)
    assert results == []
