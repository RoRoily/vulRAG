from __future__ import annotations

import json
from pathlib import Path

from mmrag.parsing.ast_parser import parse_file
from mmrag.parsing.cfg_builder import build_cfg
from mmrag.parsing.models import ParseResult
from mmrag.parsing.chunker import chunk_file
from mmrag.reasoning.llm_backend import MockLLMBackend
from mmrag.reasoning.models import LLMConfig, Verdict
from mmrag.reasoning.orchestrator import VulnerabilityAnalyzer


_MOCK_ATTACK = json.dumps({
    "vulnerability_type": "CWE-416: Use After Free",
    "confidence": 0.7,
    "source": {"line": 82, "code": "malloc", "description": "heap alloc"},
    "sink": {"line": 96, "code": "free(buffer)", "description": "free"},
    "data_flow_path": [
        {"line": 82, "code": "malloc", "description": "alloc"},
        {"line": 91, "code": "buffer[0] = flag", "description": "use"},
        {"line": 96, "code": "free(buffer)", "description": "free"},
    ],
    "reasoning": "Buffer used after potential goto skip.",
})

_MOCK_DEFENSE = json.dumps({
    "verdict": "partially_mitigated",
    "mitigations": [
        {"line": 83, "code": "if (buffer == NULL)", "description": "null check"},
    ],
    "false_positive_indicators": ["goto cleanup pattern is intentional"],
    "reasoning": "The goto pattern is a standard C error handling idiom.",
})

_MOCK_JUDGE = json.dumps({
    "verdict": "UNCERTAIN",
    "confidence": 0.5,
    "vulnerability_type": "CWE-416",
    "source_sink_path": [
        {"line": 82, "code": "malloc", "role": "source", "description": "alloc"},
        {"line": 96, "code": "free", "role": "sink", "description": "free"},
    ],
    "key_evidence": {"attack": "use after goto", "defense": "null check"},
    "summary": "Potential issue but mitigated by null check pattern.",
})


def _make_mock() -> MockLLMBackend:
    """Create a mock with routing based on unique prompt phrases."""
    mock = MockLLMBackend()
    # "security auditor" → attacker prompts, "software engineer" → defender, "impartial" → judge
    mock.set_response("security auditor", _MOCK_ATTACK)
    mock.set_response("software engineer", _MOCK_DEFENSE)
    mock.set_response("impartial", _MOCK_JUDGE)
    mock.set_default_response(_MOCK_ATTACK)
    return mock


def test_orchestrator_analyze_function():
    root, funcs, src = parse_file(str(Path(__file__).parent / "fixtures" / "sample.c"))
    by_name = {f.name: f for f in funcs}
    func = by_name["resource_handler"]
    cfg = build_cfg(func)

    mock = _make_mock()
    analyzer = VulnerabilityAnalyzer(
        llm_config=LLMConfig(model_path="/mock"),
        llm_backend=mock,
    )

    report = analyzer.analyze_function(func, cfg, src)

    assert report.function_name == "resource_handler"
    assert report.verdict in (Verdict.VULNERABLE, Verdict.SAFE, Verdict.UNCERTAIN)
    assert report.analysis_time_seconds >= 0
    assert len(report.debate_record.rounds) == 2


def test_orchestrator_analyze_function_report_structure():
    root, funcs, src = parse_file(str(Path(__file__).parent / "fixtures" / "sample.c"))
    by_name = {f.name: f for f in funcs}
    func = by_name["resource_handler"]
    cfg = build_cfg(func)

    mock = _make_mock()
    analyzer = VulnerabilityAnalyzer(
        llm_config=LLMConfig(model_path="/mock"),
        llm_backend=mock,
    )

    report = analyzer.analyze_function(func, cfg, src)

    data = json.loads(report.model_dump_json())
    assert "function_name" in data
    assert "verdict" in data
    assert "debate_record" in data
    assert "source_sink_path" in data


def test_orchestrator_five_llm_calls():
    root, funcs, src = parse_file(str(Path(__file__).parent / "fixtures" / "sample.c"))
    by_name = {f.name: f for f in funcs}
    func = by_name["resource_handler"]
    cfg = build_cfg(func)

    mock = _make_mock()
    analyzer = VulnerabilityAnalyzer(
        llm_config=LLMConfig(model_path="/mock"),
        llm_backend=mock,
    )

    analyzer.analyze_function(func, cfg, src)
    # 2-round debate: attack1, defend1, attack2, defend2, judge = 5 calls
    assert mock.call_count == 5


def test_orchestrator_skips_safe_functions():
    root, funcs, src = parse_file(str(Path(__file__).parent / "fixtures" / "sample.c"))

    mock = _make_mock()
    analyzer = VulnerabilityAnalyzer(
        llm_config=LLMConfig(model_path="/mock"),
        llm_backend=mock,
    )

    # analyze_file skips functions without dangerous calls
    reports = analyzer.analyze_file(str(Path(__file__).parent / "fixtures" / "sample.c"))
    func_names = [r.function_name for r in reports]
    assert "add" not in func_names
    assert "classify" not in func_names
