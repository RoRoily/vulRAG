from __future__ import annotations

from enum import Enum
from pydantic import BaseModel, Field
from mmrag.parsing.models import Chunk


class RetrievalSource(str, Enum):
    BM25 = "bm25"
    EMBEDDING = "embedding"
    GRAPH = "graph"
    FUSED = "fused"


class RetrievalResult(BaseModel):
    chunk_id: str
    chunk: Chunk
    score: float
    rank: int
    source: RetrievalSource


class MetadataFilter(BaseModel):
    file_paths: list[str] | None = None
    function_names: list[str] | None = None
    ast_node_types: list[str] | None = None
    kinds: list[str] | None = None


class RetrievalConfig(BaseModel):
    top_k: int = 20
    bm25_weight: float = 1.0
    embedding_weight: float = 1.0
    graph_weight: float = 0.5
    rrf_k: int = 60
    bm25_top_k_multiplier: int = 3
    embedding_top_k_multiplier: int = 3
    graph_top_k_multiplier: int = 3
    model_path: str = ""
    model_name: str = "codefuse-ai/CodeFuse-CGE-Small"
    embedding_path: str = "./mmrag_embeddings.pkl"
    bm25_path: str = "./mmrag_bm25.pkl"
    graph_path: str = "./mmrag_graph.pkl"
    embedding_batch_size: int = 64
    device: str = "auto"


class IndexStats(BaseModel):
    chunk_count: int
    bm25_indexed: bool
    embedding_indexed: bool
    graph_indexed: bool = False
    model_name: str
    embedding_path: str
    bm25_path: str
    graph_path: str = ""
