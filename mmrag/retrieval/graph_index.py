from __future__ import annotations

import pickle
from pathlib import Path

import numpy as np

from mmrag.parsing.models import CFGFeatures, Chunk
from .models import MetadataFilter, RetrievalResult, RetrievalSource

# Ordered feature dimensions — must stay consistent across build/query
_FEATURE_KEYS = [
    "num_blocks",
    "num_edges",
    "num_back_edges",
    "num_branches",
    "num_returns",
    "branch_ratio",
    "cyclomatic_complexity",
    "max_block_depth",
]


def _features_to_vec(f: CFGFeatures) -> np.ndarray:
    return np.array([getattr(f, k) for k in _FEATURE_KEYS], dtype=np.float64)


def _query_features_from_chunk(chunk: Chunk) -> np.ndarray | None:
    """Extract feature vector from a query chunk, or None if no CFG data."""
    if chunk.cfg_features is not None:
        return _features_to_vec(chunk.cfg_features)
    # Fallback: estimate from available metadata (line count as proxy)
    return np.array([
        0, 0, 0, 0, 0, 0.0, 1, 0,
    ], dtype=np.float64)


class GraphIndex:
    """
    Graph-modality index: retrieves chunks by CFG structural similarity.

    Feature vectors are L2-normalised so cosine similarity reduces to a dot
    product, matching the pattern used by EmbeddingIndex.
    """

    def __init__(self) -> None:
        self._chunk_ids: list[str] = []
        self._chunks: dict[str, Chunk] = {}
        self._matrix: np.ndarray | None = None   # shape (N, len(_FEATURE_KEYS))
        self._has_graph_data: bool = False

    def build(self, chunks: list[Chunk]) -> None:
        vecs: list[np.ndarray] = []
        ids: list[str] = []

        for chunk in chunks:
            if chunk.cfg_features is not None:
                vecs.append(_features_to_vec(chunk.cfg_features))
                ids.append(chunk.chunk_id)
                self._chunks[chunk.chunk_id] = chunk

        self._chunk_ids = ids
        self._has_graph_data = len(ids) > 0

        if vecs:
            mat = np.vstack(vecs)
            norms = np.linalg.norm(mat, axis=1, keepdims=True)
            norms = np.where(norms == 0, 1.0, norms)
            self._matrix = mat / norms
        else:
            self._matrix = None

    def query(
        self,
        query_chunk: Chunk | None = None,
        query_features: CFGFeatures | None = None,
        top_k: int = 20,
        filters: MetadataFilter | None = None,
    ) -> list[RetrievalResult]:
        """
        Query by structural similarity.

        Pass either a Chunk (uses its cfg_features) or a raw CFGFeatures object.
        Returns empty list when no graph data was indexed.
        """
        if self._matrix is None or not self._chunk_ids:
            return []

        # Build query vector
        if query_features is not None:
            qvec = _features_to_vec(query_features)
        elif query_chunk is not None:
            if query_chunk.cfg_features is not None:
                qvec = _features_to_vec(query_chunk.cfg_features)
            else:
                return []
        else:
            return []

        qnorm = np.linalg.norm(qvec)
        if qnorm == 0:
            return []
        qvec = qvec / qnorm

        scores = self._matrix @ qvec

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
                source=RetrievalSource.GRAPH,
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

    @property
    def has_graph_data(self) -> bool:
        return self._has_graph_data

    @property
    def chunk_count(self) -> int:
        return len(self._chunk_ids)

    def save(self, path: str) -> None:
        data = {
            "chunk_ids": self._chunk_ids,
            "chunks": {cid: c.model_dump(mode="json") for cid, c in self._chunks.items()},
            "matrix": self._matrix,
        }
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump(data, f)

    @classmethod
    def load(cls, path: str) -> GraphIndex:
        with open(path, "rb") as f:
            data = pickle.load(f)
        index = cls()
        index._chunk_ids = data["chunk_ids"]
        index._chunks = {cid: Chunk.model_validate(d) for cid, d in data["chunks"].items()}
        index._matrix = data["matrix"]
        index._has_graph_data = len(index._chunk_ids) > 0
        return index
