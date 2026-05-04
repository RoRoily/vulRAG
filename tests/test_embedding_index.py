from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

from mmrag.parsing.ast_parser import parse_file
from mmrag.parsing.chunker import chunk_file
from mmrag.retrieval.embedding_index import EmbeddingIndex
from mmrag.retrieval.models import MetadataFilter, RetrievalConfig


@pytest.fixture
def sample_chunks():
    root, functions, source = parse_file(
        str(Path(__file__).parent / "fixtures" / "sample.c")
    )
    return chunk_file(functions, source, "tests/fixtures/sample.c")


def _make_mock_model():
    mock = MagicMock()
    rng = np.random.RandomState(42)

    def encode_side_effect(texts, **kwargs):
        n = len(texts) if isinstance(texts, list) else 1
        emb = rng.randn(n, 64).astype(np.float32)
        norms = np.linalg.norm(emb, axis=1, keepdims=True)
        return emb / norms

    mock.encode = MagicMock(side_effect=encode_side_effect)
    return mock


@pytest.fixture
def embedding_config():
    tmpdir = tempfile.mkdtemp()
    return RetrievalConfig(
        model_path="/fake/model/path",
        device="cpu",
    )


def test_build_and_count(sample_chunks, embedding_config):
    index = EmbeddingIndex(embedding_config)
    index._model = _make_mock_model()
    index.build(sample_chunks)
    assert index.chunk_count == len(sample_chunks)


def test_query_returns_results(sample_chunks, embedding_config):
    index = EmbeddingIndex(embedding_config)
    index._model = _make_mock_model()
    index.build(sample_chunks)

    results = index.query("malloc free buffer", top_k=5)
    assert len(results) > 0
    assert results[0].rank == 1
    assert results[0].score is not None


def test_metadata_filter_kind(sample_chunks, embedding_config):
    index = EmbeddingIndex(embedding_config)
    index._model = _make_mock_model()
    index.build(sample_chunks)

    filters = MetadataFilter(kinds=["function"])
    results = index.query("test query", top_k=20, filters=filters)
    for r in results:
        assert r.chunk.kind.value == "function"


def test_metadata_filter_function_name(sample_chunks, embedding_config):
    index = EmbeddingIndex(embedding_config)
    index._model = _make_mock_model()
    index.build(sample_chunks)

    filters = MetadataFilter(function_names=["add"])
    results = index.query("test query", top_k=10, filters=filters)
    for r in results:
        assert r.chunk.function_name == "add"


def test_persistence_roundtrip(sample_chunks, embedding_config):
    index = EmbeddingIndex(embedding_config)
    index._model = _make_mock_model()
    index.build(sample_chunks)

    with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
        path = f.name

    try:
        index.save(path)
        loaded = EmbeddingIndex.load(path, embedding_config)
        loaded._model = _make_mock_model()
        assert loaded.chunk_count == index.chunk_count
    finally:
        Path(path).unlink(missing_ok=True)


def test_model_path_required():
    config = RetrievalConfig(model_path="")
    index = EmbeddingIndex(config)
    with pytest.raises(ValueError, match="model_path is required"):
        index._ensure_model()


def test_offline_env_vars_set():
    config = RetrievalConfig(model_path="/fake/model/path", device="cpu")
    index = EmbeddingIndex(config)
    try:
        index._ensure_model()
    except Exception:
        pass
    assert os.environ.get("HF_HUB_OFFLINE") == "1"
    assert os.environ.get("TRANSFORMERS_OFFLINE") == "1"
