from __future__ import annotations

import logging
import os
import pickle
from pathlib import Path

import numpy as np

from mmrag.parsing.models import Chunk
from .models import MetadataFilter, RetrievalConfig, RetrievalResult, RetrievalSource

logger = logging.getLogger(__name__)


def _resolve_device(device_cfg: str) -> str:
    if device_cfg == "auto":
        import torch
        resolved = "cuda" if torch.cuda.is_available() else "cpu"
        logger.info("Device auto-detected: %s", resolved)
        return resolved
    return device_cfg


class EmbeddingIndex:
    def __init__(self, config: RetrievalConfig) -> None:
        self._config = config
        self._model = None
        self._chunk_ids: list[str] = []
        self._chunks: dict[str, Chunk] = {}
        self._embeddings: np.ndarray | None = None

    def _ensure_model(self):
        if self._model is not None:
            return self._model

        # Constraint E: strict offline — block all HuggingFace Hub access
        os.environ["HF_HUB_OFFLINE"] = "1"
        os.environ["TRANSFORMERS_OFFLINE"] = "1"

        if not self._config.model_path:
            raise ValueError(
                "config.model_path is required for offline deployment. "
                "Provide an absolute local path to the embedding model directory."
            )

        from sentence_transformers import SentenceTransformer

        # Constraint F: dynamic device allocation
        device = _resolve_device(self._config.device)
        logger.info("Loading embedding model from %s on %s", self._config.model_path, device)

        self._model = SentenceTransformer(
            self._config.model_path,
            device=device,
            trust_remote_code=False,
            local_files_only=True,
        )
        return self._model

    def build(self, chunks: list[Chunk]) -> None:
        model = self._ensure_model()

        self._chunk_ids = [c.chunk_id for c in chunks]
        self._chunks.update({c.chunk_id: c for c in chunks})

        all_embeddings: list[np.ndarray] = []
        batch_size = self._config.embedding_batch_size
        for i in range(0, len(chunks), batch_size):
            batch = chunks[i : i + batch_size]
            texts = [c.text for c in batch]
            embeddings = model.encode(
                texts,
                show_progress_bar=False,
                normalize_embeddings=True,
            )
            all_embeddings.append(np.asarray(embeddings))

        if all_embeddings:
            self._embeddings = np.vstack(all_embeddings)
        else:
            self._embeddings = None

    def query(
        self,
        query_text: str,
        top_k: int = 20,
        filters: MetadataFilter | None = None,
    ) -> list[RetrievalResult]:
        if self._embeddings is None or len(self._chunk_ids) == 0:
            return []

        model = self._ensure_model()
        query_emb = model.encode(
            [query_text],
            normalize_embeddings=True,
        )
        query_vec = np.asarray(query_emb).flatten()

        # cosine similarity (embeddings are already L2-normalized)
        scores = self._embeddings @ query_vec

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
            chunk = self._chunks.get(cid)
            if chunk is None:
                continue
            results.append(RetrievalResult(
                chunk_id=cid,
                chunk=chunk,
                score=score,
                rank=rank,
                source=RetrievalSource.EMBEDDING,
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
            "embeddings": self._embeddings,
        }
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump(data, f)

    @classmethod
    def load(cls, path: str, config: RetrievalConfig) -> EmbeddingIndex:
        with open(path, "rb") as f:
            data = pickle.load(f)
        index = cls(config)
        index._chunk_ids = data["chunk_ids"]
        index._chunks = {cid: Chunk.model_validate(d) for cid, d in data["chunks"].items()}
        index._embeddings = data["embeddings"]
        return index

    @property
    def chunk_count(self) -> int:
        return len(self._chunk_ids)
