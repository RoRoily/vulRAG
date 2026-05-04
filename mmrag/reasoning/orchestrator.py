from __future__ import annotations

import json
import logging
import time

from mmrag.parsing.ast_parser import collect_errors, parse_file
from mmrag.parsing.cfg_builder import build_cfg
from mmrag.parsing.chunker import chunk_file
from mmrag.parsing.models import CFG, FunctionInfo, ParseResult, SliceCriterion, SliceDirection
from mmrag.parsing.slicer import compute_slice
from mmrag.retrieval.models import RetrievalConfig
from mmrag.retrieval.retriever import Retriever

from .agents import AttackerAgent, DefenderAgent, JudgeAgent
from .evidence import build_cfg_summary, find_dangerous_calls, validate_source_sink_path
from .llm_backend import LLMBackend
from .models import (
    DebateRecord,
    DebateRound,
    LLMConfig,
    Verdict,
    VulnerabilityReport,
)

logger = logging.getLogger(__name__)


class VulnerabilityAnalyzer:
    def __init__(
        self,
        llm_config: LLMConfig,
        retrieval_config: RetrievalConfig | None = None,
        llm_backend: LLMBackend | None = None,
    ) -> None:
        self._llm_config = llm_config
        self._llm = llm_backend or LLMBackend(llm_config)
        self._attacker = AttackerAgent(self._llm)
        self._defender = DefenderAgent(self._llm)
        self._judge = JudgeAgent(self._llm)
        self._retriever: Retriever | None = None
        if retrieval_config:
            try:
                self._retriever = Retriever.load(retrieval_config)
            except Exception:
                logger.warning("Could not load retriever, proceeding without retrieval context")

    def analyze_function(
        self,
        func: FunctionInfo,
        cfg: CFG,
        source: bytes,
        parse_result: ParseResult | None = None,
    ) -> VulnerabilityReport:
        t0 = time.time()
        source_text = source.decode("utf-8", errors="replace")
        source_lines = source_text.splitlines()

        # Extract function code
        func_code = func.ast.text

        # Build CFG summary
        cfg_summary = build_cfg_summary(cfg)

        # Find dangerous calls and compute slices
        dangerous = find_dangerous_calls(func)
        slice_parts: list[str] = []
        for line, api_name in dangerous:
            criterion = SliceCriterion(line=line, variable=None)
            sl = compute_slice(cfg, source, criterion, SliceDirection.BACKWARD)
            if sl.included_lines:
                slice_parts.append(
                    f"Backward slice from {api_name}() at line {line}: "
                    f"lines {sl.included_lines}\n{sl.source_text}"
                )
        slice_info = "\n\n".join(slice_parts) if slice_parts else "No dangerous API calls detected."

        # Retrieve similar patterns
        context_chunks: list[str] = []
        context_ids: list[str] = []
        if self._retriever:
            query = f"{func.name} {' '.join(api for _, api in dangerous[:5])}"
            if query.strip():
                results = self._retriever.query(query, top_k=5)
                for r in results:
                    context_chunks.append(r.chunk.text)
                    context_ids.append(r.chunk_id)

        # ---- Round 1 ----
        attack_1 = self._attacker.analyze(func_code, context_chunks, cfg_summary, slice_info)
        attack_1_json = attack_1.model_dump_json()

        defense_1 = self._defender.defend(func_code, context_chunks, attack_1_json)
        defense_1_json = defense_1.model_dump_json()

        round_1 = DebateRound(
            round_number=1,
            attacker_argument=attack_1,
            defender_argument=defense_1,
        )

        # ---- Round 2 ----
        attack_2 = self._attacker.rebut(func_code, defense_1_json, attack_1_json)
        attack_2_json = attack_2.model_dump_json()

        defense_2 = self._defender.rebut(func_code, attack_2_json, defense_1_json)

        round_2 = DebateRound(
            round_number=2,
            attacker_argument=attack_2,
            defender_argument=defense_2,
        )

        # ---- Judge ----
        debate_record = DebateRecord(rounds=[round_1, round_2])
        debate_text = debate_record.model_dump_json(indent=2)

        judge_verdict = self._judge.judge(func_code, debate_text)
        debate_record.judge_verdict = judge_verdict

        # Validate evidence chain
        validated_path = validate_source_sink_path(
            judge_verdict.source_sink_path,
            source_lines,
            cfg,
        )

        elapsed = time.time() - t0

        return VulnerabilityReport(
            function_name=func.name,
            file_path=parse_result.file_path if parse_result else "",
            source_range_start_line=func.source_range.start.line,
            source_range_end_line=func.source_range.end.line,
            verdict=judge_verdict.verdict,
            confidence=judge_verdict.confidence,
            vulnerability_type=judge_verdict.vulnerability_type,
            source_sink_path=validated_path,
            debate_record=debate_record,
            retrieved_context_ids=context_ids,
            analysis_time_seconds=round(elapsed, 2),
        )

    def analyze_file(self, file_path: str) -> list[VulnerabilityReport]:
        root, functions, source = parse_file(file_path)
        errors = collect_errors(root)
        if errors:
            logger.warning("Parse errors in %s: %d", file_path, len(errors))

        cfgs: dict[str, CFG] = {}
        for func in functions:
            cfgs[func.name] = build_cfg(func)

        chunks = chunk_file(functions, source, file_path)

        parse_result = ParseResult(
            file_path=file_path,
            language="c",
            functions=functions,
            cfgs=cfgs,
            chunks=chunks,
            errors=errors,
        )

        reports: list[VulnerabilityReport] = []
        for func in functions:
            cfg = cfgs[func.name]
            dangerous = find_dangerous_calls(func)
            if not dangerous:
                logger.info("Skipping %s — no dangerous API calls", func.name)
                continue
            report = self.analyze_function(func, cfg, source, parse_result)
            reports.append(report)

        return reports
