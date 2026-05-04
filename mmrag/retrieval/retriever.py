from __future__ import annotations

import pickle
from pathlib import Path

from mmrag.parsing.models import Chunk, ParseResult
from .bm25_index import BM25Index
from .embedding_index import EmbeddingIndex
from .fusion import reciprocal_rank_fusion
from .models import IndexStats, MetadataFilter, RetrievalConfig, RetrievalResult


class Retriever:
    def __init__(self, config: RetrievalConfig | None = None) -> None:
        self._config = config or RetrievalConfig()
        self._bm25_index: BM25Index | None = None
        self._embedding_index: EmbeddingIndex | None = None
        self._chunks: dict[str, Chunk] = {}

    def index(self, chunks: list[Chunk]) -> IndexStats:
        self._chunks.update({c.chunk_id: c for c in chunks})

        self._bm25_index = BM25Index()
        self._bm25_index.build(chunks)

        embedding_indexed = False
        if self._config.model_path:
            self._embedding_index = EmbeddingIndex(self._config)
            self._embedding_index.build(chunks)
            embedding_indexed = True

        return IndexStats(
            chunk_count=len(self._chunks),
            bm25_indexed=True,
            embedding_indexed=embedding_indexed,
            model_name=self._config.model_name,
            embedding_path=self._config.embedding_path,
            bm25_path=self._config.bm25_path,
        )

    def index_parse_results(self, results: list[ParseResult]) -> IndexStats:
        all_chunks: list[Chunk] = []
        for r in results:
            all_chunks.extend(r.chunks)
        return self.index(all_chunks)

    def query(
        self,
        query_text: str,
        top_k: int | None = None,
        filters: MetadataFilter | None = None,
    ) -> list[RetrievalResult]:
        effective_top_k = top_k or self._config.top_k
        fetch_k = effective_top_k * self._config.bm25_top_k_multiplier

        bm25_results: list[RetrievalResult] = []
        if self._bm25_index:
            bm25_results = self._bm25_index.query(query_text, top_k=fetch_k, filters=filters)

        embedding_results: list[RetrievalResult] = []
        if self._embedding_index:
            emb_fetch_k = effective_top_k * self._config.embedding_top_k_multiplier
            embedding_results = self._embedding_index.query(query_text, top_k=emb_fetch_k, filters=filters)

        if bm25_results and embedding_results:
            return reciprocal_rank_fusion(
                bm25_results,
                embedding_results,
                top_k=effective_top_k,
                rrf_k=self._config.rrf_k,
                bm25_weight=self._config.bm25_weight,
                embedding_weight=self._config.embedding_weight,
            )
        elif bm25_results:
            return bm25_results[:effective_top_k]
        elif embedding_results:
            return embedding_results[:effective_top_k]
        return []

    def query_bm25_only(
        self,
        query_text: str,
        top_k: int | None = None,
        filters: MetadataFilter | None = None,
    ) -> list[RetrievalResult]:
        if not self._bm25_index:
            return []
        return self._bm25_index.query(query_text, top_k=top_k or self._config.top_k, filters=filters)

    def query_embedding_only(
        self,
        query_text: str,
        top_k: int | None = None,
        filters: MetadataFilter | None = None,
    ) -> list[RetrievalResult]:
        if not self._embedding_index:
            return []
        return self._embedding_index.query(query_text, top_k=top_k or self._config.top_k, filters=filters)

    def save(self) -> None:
        if self._bm25_index:
            self._bm25_index.save(self._config.bm25_path)

        if self._embedding_index:
            self._embedding_index.save(self._config.embedding_path)

        registry_path = str(Path(self._config.bm25_path).with_suffix(".chunks.pkl"))
        Path(registry_path).parent.mkdir(parents=True, exist_ok=True)
        with open(registry_path, "wb") as f:
            pickle.dump(
                {cid: c.model_dump(mode="json") for cid, c in self._chunks.items()},
                f,
            )

    @classmethod
    def load(cls, config: RetrievalConfig) -> Retriever:
        retriever = cls(config)

        if Path(config.bm25_path).exists():
            retriever._bm25_index = BM25Index.load(config.bm25_path)

        registry_path = str(Path(config.bm25_path).with_suffix(".chunks.pkl"))
        if Path(registry_path).exists():
            with open(registry_path, "rb") as f:
                data = pickle.load(f)
            retriever._chunks = {cid: Chunk.model_validate(d) for cid, d in data.items()}

        if config.model_path and Path(config.embedding_path).exists():
            retriever._embedding_index = EmbeddingIndex.load(config.embedding_path, config)

        return retriever

    def stats(self) -> IndexStats:
        return IndexStats(
            chunk_count=len(self._chunks),
            bm25_indexed=self._bm25_index is not None,
            embedding_indexed=self._embedding_index is not None,
            model_name=self._config.model_name,
            embedding_path=self._config.embedding_path,
            bm25_path=self._config.bm25_path,
        )
