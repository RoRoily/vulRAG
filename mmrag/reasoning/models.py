from __future__ import annotations

from enum import Enum
from pydantic import BaseModel, Field


class Verdict(str, Enum):
    VULNERABLE = "VULNERABLE"
    SAFE = "SAFE"
    UNCERTAIN = "UNCERTAIN"


class DefenseVerdict(str, Enum):
    SAFE = "safe"
    PARTIALLY_MITIGATED = "partially_mitigated"
    UNMITIGATED = "unmitigated"


class SourceSinkRole(str, Enum):
    SOURCE = "source"
    PROPAGATION = "propagation"
    SINK = "sink"


class LLMConfig(BaseModel):
    model_path: str = ""
    n_gpu_layers: int = -1
    n_ctx: int = 16384
    n_threads: int = 4
    temperature: float = 0.1
    max_tokens: int = 2048
    seed: int = 42
    device: str = "auto"


class SourceSinkPoint(BaseModel):
    line: int
    column: int = 0
    code: str = ""
    description: str = ""
    role: SourceSinkRole = SourceSinkRole.PROPAGATION


class AttackArgument(BaseModel):
    vulnerability_type: str = ""
    confidence: float = 0.0
    source: SourceSinkPoint | None = None
    sink: SourceSinkPoint | None = None
    data_flow_path: list[SourceSinkPoint] = Field(default_factory=list)
    reasoning: str = ""


class DefenseArgument(BaseModel):
    verdict: DefenseVerdict = DefenseVerdict.UNMITIGATED
    mitigations: list[SourceSinkPoint] = Field(default_factory=list)
    false_positive_indicators: list[str] = Field(default_factory=list)
    reasoning: str = ""


class JudgeVerdict(BaseModel):
    verdict: Verdict = Verdict.UNCERTAIN
    confidence: float = 0.0
    vulnerability_type: str | None = None
    source_sink_path: list[SourceSinkPoint] = Field(default_factory=list)
    key_evidence: dict[str, str] = Field(default_factory=dict)
    summary: str = ""


class DebateRound(BaseModel):
    round_number: int
    attacker_argument: AttackArgument
    defender_argument: DefenseArgument


class DebateRecord(BaseModel):
    rounds: list[DebateRound] = Field(default_factory=list)
    judge_verdict: JudgeVerdict | None = None


class VulnerabilityReport(BaseModel):
    function_name: str
    file_path: str
    source_range_start_line: int
    source_range_end_line: int
    verdict: Verdict
    confidence: float
    vulnerability_type: str | None = None
    source_sink_path: list[SourceSinkPoint] = Field(default_factory=list)
    debate_record: DebateRecord = Field(default_factory=DebateRecord)
    retrieved_context_ids: list[str] = Field(default_factory=list)
    analysis_time_seconds: float = 0.0
