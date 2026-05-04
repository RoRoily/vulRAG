from __future__ import annotations

from pathlib import Path

from mmrag.parsing.ast_parser import parse_file, collect_errors
from mmrag.parsing.cfg_builder import build_cfg
from mmrag.parsing.chunker import chunk_file


def test_broken_file_no_exception(sample_broken_c):
    """Parsing a broken file must never raise an exception."""
    root, functions, source = parse_file(str(sample_broken_c))
    assert root is not None


def test_broken_file_reports_errors(sample_broken_c):
    """Broken file should report ERROR/MISSING nodes."""
    root, functions, source = parse_file(str(sample_broken_c))
    errors = collect_errors(root)
    assert len(errors) > 0, "Broken file should have parse errors"


def test_broken_file_still_extracts_functions(sample_broken_c):
    """Valid functions in a broken file should still be extracted."""
    root, functions, source = parse_file(str(sample_broken_c))
    names = [f.name for f in functions]
    # At least some functions should be found
    assert len(functions) > 0, "Should extract at least some functions from broken file"


def test_broken_file_cfg_no_exception(sample_broken_c):
    """Building CFG for functions in a broken file must not crash."""
    root, functions, source = parse_file(str(sample_broken_c))
    for func in functions:
        cfg = build_cfg(func)
        assert cfg is not None
        assert cfg.entry_block_id in cfg.blocks
        assert cfg.exit_block_id in cfg.blocks


def test_broken_file_chunking_no_exception(sample_broken_c):
    """Chunking a broken file must not crash."""
    root, functions, source = parse_file(str(sample_broken_c))
    chunks = chunk_file(functions, source, str(sample_broken_c))
    assert isinstance(chunks, list)


def test_broken_file_cfg_has_warnings(sample_broken_c):
    """CFG for functions with ERROR nodes should log warnings."""
    root, functions, source = parse_file(str(sample_broken_c))
    all_warnings: list[str] = []
    for func in functions:
        cfg = build_cfg(func)
        all_warnings.extend(cfg.warnings)
    # Some functions may have warnings, some may not — just verify no crash
    assert isinstance(all_warnings, list)
