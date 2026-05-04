from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from mmrag.parsing.ast_parser import parse_file
from mmrag.parsing.chunker import chunk_file
from mmrag.retrieval.models import MetadataFilter, RetrievalConfig
from mmrag.retrieval.retriever import Retriever


@pytest.fixture
def sample_chunks():
    root, functions, source = parse_file(
        str(Path(__file__).parent / "fixtures" / "sample.c")
    )
    return chunk_file(functions, source, "tests/fixtures/sample.c")


def test_bm25_only_query(sample_chunks):
    config = RetrievalConfig()
    retriever = Retriever(config)
    retriever.index(sample_chunks)

    results = retriever.query_bm25_only("malloc free buffer", top_k=5)
    assert len(results) > 0
    assert results[0].rank == 1


def test_query_falls_back_to_bm25_without_model(sample_chunks):
    config = RetrievalConfig(model_path="")
    retriever = Retriever(config)
    retriever.index(sample_chunks)

    results = retriever.query("malloc free buffer", top_k=5)
    assert len(results) > 0


def test_query_with_filter(sample_chunks):
    config = RetrievalConfig()
    retriever = Retriever(config)
    retriever.index(sample_chunks)

    filters = MetadataFilter(function_names=["resource_handler"])
    results = retriever.query_bm25_only("buffer malloc", top_k=10, filters=filters)
    for r in results:
        assert r.chunk.function_name == "resource_handler"


def test_save_and_load(sample_chunks):
    with tempfile.TemporaryDirectory() as tmpdir:
        bm25_path = str(Path(tmpdir) / "test_bm25.pkl")
        config = RetrievalConfig(bm25_path=bm25_path, db_path=str(Path(tmpdir) / "chromadb"))

        retriever = Retriever(config)
        retriever.index(sample_chunks)
        retriever.save()

        loaded = Retriever.load(config)
        assert loaded.stats().chunk_count == len(sample_chunks)
        assert loaded.stats().bm25_indexed

        results = loaded.query_bm25_only("malloc buffer", top_k=5)
        assert len(results) > 0


def test_stats(sample_chunks):
    retriever = Retriever(RetrievalConfig())
    retriever.index(sample_chunks)
    stats = retriever.stats()
    assert stats.chunk_count == len(sample_chunks)
    assert stats.bm25_indexed
    assert not stats.embedding_indexed


def test_empty_query(sample_chunks):
    retriever = Retriever(RetrievalConfig())
    retriever.index(sample_chunks)
    results = retriever.query("", top_k=5)
    assert results == []
