from __future__ import annotations

import json

from mmrag.reasoning.models import (
    AttackArgument,
    DebateRecord,
    DebateRound,
    DefenseArgument,
    JudgeVerdict,
    LLMConfig,
    SourceSinkPoint,
    SourceSinkRole,
    Verdict,
    VulnerabilityReport,
)


def test_llm_config_defaults():
    cfg = LLMConfig(model_path="/test.gguf")
    assert cfg.n_ctx == 16384
    assert cfg.n_gpu_layers == -1
    assert cfg.device == "auto"
    assert cfg.temperature == 0.1


def test_source_sink_point_serialization():
    p = SourceSinkPoint(line=42, code="strcpy(dst, src)", description="unsafe copy", role=SourceSinkRole.SINK)
    data = p.model_dump(mode="json")
    assert data["line"] == 42
    assert data["role"] == "sink"
    restored = SourceSinkPoint.model_validate(data)
    assert restored.line == 42
    assert restored.role == SourceSinkRole.SINK


def test_attack_argument_roundtrip():
    arg = AttackArgument(
        vulnerability_type="CWE-122: Heap-based Buffer Overflow",
        confidence=0.85,
        source=SourceSinkPoint(line=10, code="buf = malloc(n)", role=SourceSinkRole.SOURCE),
        sink=SourceSinkPoint(line=20, code="strcpy(buf, input)", role=SourceSinkRole.SINK),
        data_flow_path=[
            SourceSinkPoint(line=15, code="input = gets(tmp)", role=SourceSinkRole.PROPAGATION),
        ],
        reasoning="Unchecked buffer copy",
    )
    j = arg.model_dump_json()
    restored = AttackArgument.model_validate_json(j)
    assert restored.confidence == 0.85
    assert restored.source.line == 10
    assert len(restored.data_flow_path) == 1


def test_defense_argument_roundtrip():
    arg = DefenseArgument(
        verdict="partially_mitigated",
        mitigations=[SourceSinkPoint(line=12, code="if (n > MAX) return;", role=SourceSinkRole.PROPAGATION)],
        false_positive_indicators=["bounded by MAX constant"],
        reasoning="Size is checked before use",
    )
    j = arg.model_dump_json()
    restored = DefenseArgument.model_validate_json(j)
    assert restored.verdict == "partially_mitigated"
    assert len(restored.mitigations) == 1


def test_judge_verdict_roundtrip():
    v = JudgeVerdict(
        verdict=Verdict.VULNERABLE,
        confidence=0.9,
        vulnerability_type="CWE-122",
        source_sink_path=[
            SourceSinkPoint(line=10, code="malloc", role=SourceSinkRole.SOURCE),
            SourceSinkPoint(line=20, code="strcpy", role=SourceSinkRole.SINK),
        ],
        key_evidence={"attack": "unchecked copy", "defense": "partial bounds check"},
        summary="Vulnerable due to incomplete bounds checking",
    )
    j = v.model_dump_json()
    restored = JudgeVerdict.model_validate_json(j)
    assert restored.verdict == Verdict.VULNERABLE
    assert len(restored.source_sink_path) == 2


def test_debate_record_full():
    record = DebateRecord(
        rounds=[
            DebateRound(
                round_number=1,
                attacker_argument=AttackArgument(vulnerability_type="CWE-416", confidence=0.7),
                defender_argument=DefenseArgument(verdict="safe"),
            ),
            DebateRound(
                round_number=2,
                attacker_argument=AttackArgument(vulnerability_type="CWE-416", confidence=0.5),
                defender_argument=DefenseArgument(verdict="safe"),
            ),
        ],
        judge_verdict=JudgeVerdict(verdict=Verdict.SAFE, confidence=0.8),
    )
    j = record.model_dump_json()
    restored = DebateRecord.model_validate_json(j)
    assert len(restored.rounds) == 2
    assert restored.judge_verdict.verdict == Verdict.SAFE


def test_vulnerability_report_serialization():
    report = VulnerabilityReport(
        function_name="test_func",
        file_path="test.c",
        source_range_start_line=10,
        source_range_end_line=30,
        verdict=Verdict.VULNERABLE,
        confidence=0.85,
        vulnerability_type="CWE-122",
        analysis_time_seconds=2.5,
    )
    data = json.loads(report.model_dump_json())
    assert data["verdict"] == "VULNERABLE"
    assert data["function_name"] == "test_func"
