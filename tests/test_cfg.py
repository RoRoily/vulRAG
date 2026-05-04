from __future__ import annotations

from mmrag.parsing.cfg_builder import build_cfg
from mmrag.parsing.models import CFGEdgeKind


def test_linear_function_cfg(parsed_sample):
    root, functions, source = parsed_sample
    by_name = {f.name: f for f in functions}
    cfg = build_cfg(by_name["add"])

    assert cfg.function_name == "add"
    assert cfg.entry_block_id in cfg.blocks
    assert cfg.exit_block_id in cfg.blocks
    assert cfg.blocks[cfg.entry_block_id].is_entry
    assert cfg.blocks[cfg.exit_block_id].is_exit

    has_return = any(e.kind == CFGEdgeKind.RETURN for e in cfg.edges)
    assert has_return


def test_if_else_cfg(parsed_sample):
    root, functions, source = parsed_sample
    by_name = {f.name: f for f in functions}
    cfg = build_cfg(by_name["classify"])

    true_edges = [e for e in cfg.edges if e.kind == CFGEdgeKind.TRUE_BRANCH]
    false_edges = [e for e in cfg.edges if e.kind == CFGEdgeKind.FALSE_BRANCH]
    assert len(true_edges) >= 2
    assert len(false_edges) >= 2


def test_loop_cfg(parsed_sample):
    root, functions, source = parsed_sample
    by_name = {f.name: f for f in functions}
    cfg = build_cfg(by_name["loop_examples"])

    back_edges = [e for e in cfg.edges if e.kind == CFGEdgeKind.BACK_EDGE]
    assert len(back_edges) >= 2

    break_edges = [e for e in cfg.edges if e.kind == CFGEdgeKind.BREAK]
    assert len(break_edges) >= 1


def test_switch_cfg(parsed_sample):
    root, functions, source = parsed_sample
    by_name = {f.name: f for f in functions}
    cfg = build_cfg(by_name["status_string"])

    case_edges = [e for e in cfg.edges if e.kind == CFGEdgeKind.CASE]
    default_edges = [e for e in cfg.edges if e.kind == CFGEdgeKind.DEFAULT]
    assert len(case_edges) >= 3
    assert len(default_edges) >= 1


def test_goto_cfg(parsed_sample):
    root, functions, source = parsed_sample
    by_name = {f.name: f for f in functions}
    cfg = build_cfg(by_name["resource_handler"])

    goto_edges = [e for e in cfg.edges if e.kind == CFGEdgeKind.GOTO]
    assert len(goto_edges) >= 2


def test_entry_exit_reachability(parsed_sample):
    root, functions, source = parsed_sample
    by_name = {f.name: f for f in functions}

    for func_name in ["add", "classify", "loop_examples", "status_string"]:
        cfg = build_cfg(by_name[func_name])
        entry = cfg.blocks[cfg.entry_block_id]
        assert len(entry.successors) > 0, f"{func_name}: entry has no successors"

        exit_block = cfg.blocks[cfg.exit_block_id]
        assert len(exit_block.predecessors) > 0, f"{func_name}: exit has no predecessors"


def test_no_warnings_for_clean_functions(parsed_sample):
    root, functions, source = parsed_sample
    by_name = {f.name: f for f in functions}

    for name in ["add", "classify", "loop_examples", "status_string", "resource_handler"]:
        cfg = build_cfg(by_name[name])
        non_preproc_warnings = [
            w for w in cfg.warnings
            if "preproc" not in w and "ERROR" not in w and "MISSING" not in w
        ]
        assert len(non_preproc_warnings) == 0, f"{name}: unexpected warnings: {non_preproc_warnings}"
