from __future__ import annotations

import json

from mmrag.reasoning.agents import AttackerAgent, DefenderAgent, JudgeAgent
from mmrag.reasoning.llm_backend import MockLLMBackend
from mmrag.reasoning.models import Verdict


_MOCK_ATTACK_RESPONSE = json.dumps({
    "vulnerability_type": "CWE-122: Heap-based Buffer Overflow",
    "confidence": 0.85,
    "source": {"line": 3, "code": "malloc(MAX_SIZE)", "description": "heap allocation"},
    "sink": {"line": 5, "code": "buffer[0] = flag", "description": "unchecked write"},
    "data_flow_path": [
        {"line": 3, "code": "malloc(MAX_SIZE)", "description": "allocation"},
        {"line": 5, "code": "buffer[0] = flag", "description": "write"},
    ],
    "reasoning": "Buffer allocated without size validation, written without bounds check.",
})

_MOCK_DEFENSE_RESPONSE = json.dumps({
    "verdict": "partially_mitigated",
    "mitigations": [
        {"line": 4, "code": "if (buffer == NULL) goto cleanup", "description": "null check"},
    ],
    "false_positive_indicators": ["NULL check present", "single element write"],
    "reasoning": "The NULL check prevents use of failed allocation. Write is to index 0 only.",
})

_MOCK_JUDGE_RESPONSE = json.dumps({
    "verdict": "SAFE",
    "confidence": 0.75,
    "vulnerability_type": None,
    "source_sink_path": [],
    "key_evidence": {
        "attack": "Unchecked buffer write",
        "defense": "NULL check and bounded index",
    },
    "summary": "The function has adequate safety checks for the single-element write pattern.",
})


def test_attacker_agent_parses_response():
    mock = MockLLMBackend()
    mock.set_default_response(_MOCK_ATTACK_RESPONSE)
    agent = AttackerAgent(mock)

    result = agent.analyze("int x = malloc(10);", [], "Blocks: 3", "No slices")
    assert result.vulnerability_type == "CWE-122: Heap-based Buffer Overflow"
    assert result.confidence == 0.85
    assert result.source is not None
    assert result.source.line == 3
    assert result.sink is not None
    assert len(result.data_flow_path) == 2


def test_attacker_agent_rebut():
    mock = MockLLMBackend()
    mock.set_default_response(_MOCK_ATTACK_RESPONSE)
    agent = AttackerAgent(mock)

    result = agent.rebut("code", '{"verdict": "safe"}', '{"vulnerability_type": "CWE-122"}')
    assert result.vulnerability_type != ""


def test_defender_agent_parses_response():
    mock = MockLLMBackend()
    mock.set_default_response(_MOCK_DEFENSE_RESPONSE)
    agent = DefenderAgent(mock)

    result = agent.defend("int x = malloc(10);", [], '{"vulnerability_type": "CWE-122"}')
    assert result.verdict == "partially_mitigated"
    assert len(result.mitigations) == 1
    assert len(result.false_positive_indicators) == 2


def test_defender_agent_rebut():
    mock = MockLLMBackend()
    mock.set_default_response(_MOCK_DEFENSE_RESPONSE)
    agent = DefenderAgent(mock)

    result = agent.rebut("code", '{"vulnerability_type": "CWE-122"}', '{"verdict": "safe"}')
    assert result.reasoning != ""


def test_judge_agent_parses_response():
    mock = MockLLMBackend()
    mock.set_default_response(_MOCK_JUDGE_RESPONSE)
    agent = JudgeAgent(mock)

    result = agent.judge("int x = malloc(10);", '{"rounds": []}')
    assert result.verdict == Verdict.SAFE
    assert result.confidence == 0.75
    assert "attack" in result.key_evidence


def test_agent_handles_bad_json():
    mock = MockLLMBackend()
    mock.set_default_response("not valid json at all")
    agent = AttackerAgent(mock)

    result = agent.analyze("code", [], "", "")
    assert result.reasoning != ""


def test_mock_llm_call_count():
    mock = MockLLMBackend()
    mock.set_default_response(_MOCK_ATTACK_RESPONSE)
    agent = AttackerAgent(mock)

    agent.analyze("code", [], "", "")
    assert mock.call_count == 1

    agent.rebut("code", "{}", "{}")
    assert mock.call_count == 2


def test_mock_llm_keyword_routing():
    mock = MockLLMBackend()
    mock.set_response("malloc", _MOCK_ATTACK_RESPONSE)
    mock.set_response("safe", _MOCK_DEFENSE_RESPONSE)
    mock.set_default_response(_MOCK_JUDGE_RESPONSE)

    attacker = AttackerAgent(mock)
    result = attacker.analyze("malloc(10)", [], "", "")
    assert "CWE-122" in result.vulnerability_type

    defender = DefenderAgent(mock)
    result = defender.defend("code", [], '{"verdict": "safe"}')
    assert result.verdict == "partially_mitigated"
