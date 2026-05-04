from __future__ import annotations

import pickle
from pathlib import Path

import numpy as np
from rank_bm25 import BM25Okapi

from mmrag.parsing.models import Chunk
from .models import MetadataFilter, RetrievalResult, RetrievalSource
from .tokenizer import tokenize_code, tokenize_query


class BM25Index:
    def __init__(self) -> None:
        self._bm25: BM25Okapi | None = None
        self._chunk_ids: list[str] = []
        self._chunks: dict[str, Chunk] = {}
        self._tokenized_corpus: list[list[str]] = []

    def build(self, chunks: list[Chunk]) -> None:
        self._chunk_ids = [c.chunk_id for c in chunks]
        self._chunks = {c.chunk_id: c for c in chunks}
        self._tokenized_corpus = [tokenize_code(c.text) for c in chunks]
        if self._tokenized_corpus:
            self._bm25 = BM25Okapi(self._tokenized_corpus)
        else:
            self._bm25 = None

    def query(
        self,
        query_text: str,
        top_k: int = 20,
        filters: MetadataFilter | None = None,
    ) -> list[RetrievalResult]:
        if self._bm25 is None or not self._chunk_ids:
            return []

        query_tokens = tokenize_query(query_text)
        if not query_tokens:
            return []

        scores = self._bm25.get_scores(query_tokens)

        if filters:
            mask = self._build_filter_mask(filters)
            scores = scores * mask

        top_indices = np.argsort(scores)[::-1][:top_k]

        results: list[RetrievalResult] = []
        rank = 1
        for idx in top_indices:
            score = float(scores[idx])
            if score <= 0:
                break
            cid = self._chunk_ids[idx]
            results.append(RetrievalResult(
                chunk_id=cid,
                chunk=self._chunks[cid],
                score=score,
                rank=rank,
                source=RetrievalSource.BM25,
            ))
            rank += 1
        return results

    def _build_filter_mask(self, filters: MetadataFilter) -> np.ndarray:
        mask = np.ones(len(self._chunk_ids), dtype=np.float64)
        for i, cid in enumerate(self._chunk_ids):
            chunk = self._chunks[cid]
            if filters.file_paths and chunk.file_path not in filters.file_paths:
                mask[i] = 0.0
            elif filters.function_names and (chunk.function_name or "") not in filters.function_names:
                mask[i] = 0.0
            elif filters.kinds and chunk.kind.value not in filters.kinds:
                mask[i] = 0.0
            elif filters.ast_node_types:
                if not all(t in chunk.ast_node_types for t in filters.ast_node_types):
                    mask[i] = 0.0
        return mask

    def save(self, path: str) -> None:
        data = {
            "chunk_ids": self._chunk_ids,
            "chunks": {cid: c.model_dump(mode="json") for cid, c in self._chunks.items()},
            "tokenized_corpus": self._tokenized_corpus,
        }
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump(data, f)

    @classmethod
    def load(cls, path: str) -> BM25Index:
        with open(path, "rb") as f:
            data = pickle.load(f)
        index = cls()
        index._chunk_ids = data["chunk_ids"]
        index._chunks = {cid: Chunk.model_validate(d) for cid, d in data["chunks"].items()}
        index._tokenized_corpus = data["tokenized_corpus"]
        if index._tokenized_corpus:
            index._bm25 = BM25Okapi(index._tokenized_corpus)
        return index

    @property
    def chunk_count(self) -> int:
        return len(self._chunk_ids)
