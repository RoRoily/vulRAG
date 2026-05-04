from __future__ import annotations

from enum import Enum
from pydantic import BaseModel, Field


class VulnLabel(str, Enum):
    VULNERABLE = "vulnerable"
    SAFE = "safe"


class AffectedLine(BaseModel):
    line: int
    description: str = ""


class BenchmarkSample(BaseModel):
    sample_id: str
    file_path: str = ""
    language: str = "c"
    label: VulnLabel
    cwe_id: str | None = None
    cwe_name: str | None = None
    function_name: str | None = None
    affected_lines: list[AffectedLine] = Field(default_factory=list)
    description: str = ""
    source_code: str = ""
    tags: list[str] = Field(default_factory=list)


class RetrievalGoldItem(BaseModel):
    query: str
    relevant_chunk_ids: list[str]
    sample_id: str


class RetrievalMetrics(BaseModel):
    recall_at_k: dict[int, float] = Field(default_factory=dict)
    precision_at_k: dict[int, float] = Field(default_factory=dict)
    mrr: float = 0.0
    ndcg_at_k: dict[int, float] = Field(default_factory=dict)
    num_queries: int = 0


class DetectionResult(BaseModel):
    sample_id: str
    predicted_label: VulnLabel
    predicted_cwe: str | None = None
    confidence: float = 0.0
    true_label: VulnLabel
    true_cwe: str | None = None
    correct: bool = False
    line_overlap: float = 0.0


class DetectionMetrics(BaseModel):
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    total_samples: int = 0
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    per_cwe: dict[str, dict[str, float]] = Field(default_factory=dict)
    results: list[DetectionResult] = Field(default_factory=list)


class BenchmarkReport(BaseModel):
    dataset_name: str
    num_samples: int
    retrieval_metrics: RetrievalMetrics | None = None
    detection_metrics: DetectionMetrics | None = None
    config_snapshot: dict = Field(default_factory=dict)
