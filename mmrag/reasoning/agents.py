from __future__ import annotations

import json
import logging

from .grammars import ATTACKER_GRAMMAR, DEFENDER_GRAMMAR, JUDGE_GRAMMAR
from .llm_backend import LLMBackend
from .models import (
    AttackArgument,
    DefenseArgument,
    JudgeVerdict,
    SourceSinkPoint,
    SourceSinkRole,
    Verdict,
)
from .prompts import (
    build_attacker_prompt,
    build_attacker_rebuttal_prompt,
    build_defender_prompt,
    build_defender_rebuttal_prompt,
    build_judge_prompt,
)

logger = logging.getLogger(__name__)


def _parse_json_safe(text: str) -> dict:
    text = text.strip()
    if not text.startswith("{"):
        start = text.find("{")
        if start != -1:
            text = text[start:]
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        logger.warning("Failed to parse LLM JSON output: %s", text[:200])
        return {}


def _parse_point(d: dict) -> SourceSinkPoint:
    return SourceSinkPoint(
        line=d.get("line", 0),
        code=d.get("code", ""),
        description=d.get("description", ""),
        role=d.get("role", "propagation"),
    )


def _parse_attack(data: dict) -> AttackArgument:
    source = _parse_point(data["source"]) if data.get("source") else None
    sink = _parse_point(data["sink"]) if data.get("sink") else None
    path = [_parse_point(p) for p in data.get("data_flow_path", [])]
    return AttackArgument(
        vulnerability_type=data.get("vulnerability_type", ""),
        confidence=float(data.get("confidence", 0.0)),
        source=source,
        sink=sink,
        data_flow_path=path,
        reasoning=data.get("reasoning", ""),
    )


def _parse_defense(data: dict) -> DefenseArgument:
    mitigations = [_parse_point(p) for p in data.get("mitigations", [])]
    return DefenseArgument(
        verdict=data.get("verdict", "unmitigated"),
        mitigations=mitigations,
        false_positive_indicators=data.get("false_positive_indicators", []),
        reasoning=data.get("reasoning", ""),
    )


def _parse_judge(data: dict) -> JudgeVerdict:
    path = []
    for p in data.get("source_sink_path", []):
        path.append(SourceSinkPoint(
            line=p.get("line", 0),
            code=p.get("code", ""),
            description=p.get("description", ""),
            role=p.get("role", "propagation"),
        ))
    return JudgeVerdict(
        verdict=data.get("verdict", "UNCERTAIN"),
        confidence=float(data.get("confidence", 0.0)),
        vulnerability_type=data.get("vulnerability_type"),
        source_sink_path=path,
        key_evidence=data.get("key_evidence", {}),
        summary=data.get("summary", ""),
    )


class AttackerAgent:
    def __init__(self, llm: LLMBackend) -> None:
        self._llm = llm

    def analyze(
        self,
        code: str,
        context_chunks: list[str],
        cfg_summary: str,
        slice_info: str,
    ) -> AttackArgument:
        prompt = build_attacker_prompt(code, context_chunks, cfg_summary, slice_info)
        return self._call(prompt)

    def rebut(
        self,
        code: str,
        defender_argument: str,
        original_attack: str,
    ) -> AttackArgument:
        prompt = build_attacker_rebuttal_prompt(code, defender_argument, original_attack)
        return self._call(prompt)

    def _call(self, prompt: str) -> AttackArgument:
        try:
            raw = self._llm.generate_structured(prompt, ATTACKER_GRAMMAR)
            data = _parse_json_safe(raw)
            if data:
                return _parse_attack(data)
        except Exception as e:
            logger.warning("Attacker generation failed: %s, retrying...", e)
        try:
            raw = self._llm.generate_structured(prompt, ATTACKER_GRAMMAR, temperature=0.3)
            data = _parse_json_safe(raw)
            if data:
                return _parse_attack(data)
        except Exception as e:
            logger.error("Attacker retry failed: %s", e)
        return AttackArgument(reasoning="Analysis failed — could not generate structured output.")


class DefenderAgent:
    def __init__(self, llm: LLMBackend) -> None:
        self._llm = llm

    def defend(
        self,
        code: str,
        context_chunks: list[str],
        attacker_argument: str,
    ) -> DefenseArgument:
        prompt = build_defender_prompt(code, context_chunks, attacker_argument)
        return self._call(prompt)

    def rebut(
        self,
        code: str,
        attacker_rebuttal: str,
        original_defense: str,
    ) -> DefenseArgument:
        prompt = build_defender_rebuttal_prompt(code, attacker_rebuttal, original_defense)
        return self._call(prompt)

    def _call(self, prompt: str) -> DefenseArgument:
        try:
            raw = self._llm.generate_structured(prompt, DEFENDER_GRAMMAR)
            data = _parse_json_safe(raw)
            if data:
                return _parse_defense(data)
        except Exception as e:
            logger.warning("Defender generation failed: %s, retrying...", e)
        try:
            raw = self._llm.generate_structured(prompt, DEFENDER_GRAMMAR, temperature=0.3)
            data = _parse_json_safe(raw)
            if data:
                return _parse_defense(data)
        except Exception as e:
            logger.error("Defender retry failed: %s", e)
        return DefenseArgument(reasoning="Defense failed — could not generate structured output.")


class JudgeAgent:
    def __init__(self, llm: LLMBackend) -> None:
        self._llm = llm

    def judge(self, code: str, debate_record: str) -> JudgeVerdict:
        prompt = build_judge_prompt(code, debate_record)
        try:
            raw = self._llm.generate_structured(prompt, JUDGE_GRAMMAR)
            data = _parse_json_safe(raw)
            if data:
                return _parse_judge(data)
        except Exception as e:
            logger.warning("Judge generation failed: %s, retrying...", e)
        try:
            raw = self._llm.generate_structured(prompt, JUDGE_GRAMMAR, temperature=0.3)
            data = _parse_json_safe(raw)
            if data:
                return _parse_judge(data)
        except Exception as e:
            logger.error("Judge retry failed: %s", e)
        return JudgeVerdict(
            verdict=Verdict.UNCERTAIN,
            summary="Judgment failed — could not generate structured output.",
        )
