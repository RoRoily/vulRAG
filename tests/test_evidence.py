from __future__ import annotations

from pathlib import Path

from mmrag.parsing.ast_parser import parse_file
from mmrag.parsing.cfg_builder import build_cfg
from mmrag.reasoning.evidence import (
    build_cfg_summary,
    find_dangerous_calls,
    validate_source_sink_path,
)
from mmrag.reasoning.models import SourceSinkPoint, SourceSinkRole


def test_find_dangerous_calls():
    root, funcs, src = parse_file(str(Path(__file__).parent / "fixtures" / "sample.c"))
    by_name = {f.name: f for f in funcs}

    calls = find_dangerous_calls(by_name["resource_handler"])
    api_names = [name for _, name in calls]
    assert "malloc" in api_names
    assert "free" in api_names


def test_find_dangerous_calls_safe_function():
    root, funcs, src = parse_file(str(Path(__file__).parent / "fixtures" / "sample.c"))
    by_name = {f.name: f for f in funcs}

    calls = find_dangerous_calls(by_name["add"])
    assert calls == []


def test_find_dangerous_calls_printf():
    root, funcs, src = parse_file(str(Path(__file__).parent / "fixtures" / "sample.c"))
    by_name = {f.name: f for f in funcs}

    calls = find_dangerous_calls(by_name["loop_examples"])
    api_names = [name for _, name in calls]
    assert "printf" in api_names


def test_build_cfg_summary():
    root, funcs, src = parse_file(str(Path(__file__).parent / "fixtures" / "sample.c"))
    by_name = {f.name: f for f in funcs}
    cfg = build_cfg(by_name["resource_handler"])

    summary = build_cfg_summary(cfg)
    assert "Blocks:" in summary
    assert "Edges:" in summary
    assert "goto" in summary.lower()


def test_build_cfg_summary_simple():
    root, funcs, src = parse_file(str(Path(__file__).parent / "fixtures" / "sample.c"))
    by_name = {f.name: f for f in funcs}
    cfg = build_cfg(by_name["add"])

    summary = build_cfg_summary(cfg)
    assert "Blocks:" in summary


def test_validate_path_valid_lines():
    source_lines = [""] * 100
    source_lines[9] = "buf = malloc(n);"
    source_lines[19] = "strcpy(buf, input);"

    path = [
        SourceSinkPoint(line=10, code="buf = malloc(n);", role=SourceSinkRole.SOURCE),
        SourceSinkPoint(line=20, code="strcpy(buf, input);", role=SourceSinkRole.SINK),
    ]
    validated = validate_source_sink_path(path, source_lines)
    assert len(validated) == 2
    assert validated[0].line == 10
    assert validated[1].line == 20


def test_validate_path_removes_invalid_lines():
    source_lines = ["line"] * 10

    path = [
        SourceSinkPoint(line=5, code="ok", role=SourceSinkRole.SOURCE),
        SourceSinkPoint(line=999, code="bad", role=SourceSinkRole.SINK),
        SourceSinkPoint(line=0, code="bad", role=SourceSinkRole.PROPAGATION),
    ]
    validated = validate_source_sink_path(path, source_lines)
    assert len(validated) == 1
    assert validated[0].line == 5


def test_validate_path_fills_code():
    source_lines = ["", "", "", "", "int x = malloc(10);"]

    path = [
        SourceSinkPoint(line=5, code="", role=SourceSinkRole.SOURCE),
    ]
    validated = validate_source_sink_path(path, source_lines)
    assert len(validated) == 1
    assert "malloc" in validated[0].code


def test_validate_path_with_cfg():
    root, funcs, src = parse_file(str(Path(__file__).parent / "fixtures" / "sample.c"))
    by_name = {f.name: f for f in funcs}
    cfg = build_cfg(by_name["resource_handler"])
    source_lines = src.decode("utf-8", errors="replace").splitlines()

    path = [
        SourceSinkPoint(line=82, code="", role=SourceSinkRole.SOURCE),
        SourceSinkPoint(line=96, code="", role=SourceSinkRole.SINK),
    ]
    validated = validate_source_sink_path(path, source_lines, cfg)
    assert len(validated) >= 1
    for p in validated:
        assert 1 <= p.line <= len(source_lines)
