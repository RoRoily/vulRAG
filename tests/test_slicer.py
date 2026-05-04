from __future__ import annotations

from mmrag.parsing.cfg_builder import build_cfg
from mmrag.parsing.models import SliceCriterion, SliceDirection
from mmrag.parsing.slicer import compute_slice, _extract_def_use


def test_backward_slice_classify(parsed_sample):
    """Backward slice from 'return result' should include the assignments to result."""
    root, functions, source = parsed_sample
    by_name = {f.name: f for f in functions}
    cfg = build_cfg(by_name["classify"])

    criterion = SliceCriterion(line=28, variable="result")
    sl = compute_slice(cfg, source, criterion, SliceDirection.BACKWARD)

    assert sl.function_name == "classify"
    assert len(sl.included_lines) > 0
    assert 28 in sl.included_lines


def test_forward_slice_classify(parsed_sample):
    """Forward slice from 'int result;' declaration should reach the return."""
    root, functions, source = parsed_sample
    by_name = {f.name: f for f in functions}
    cfg = build_cfg(by_name["classify"])

    criterion = SliceCriterion(line=20, variable="result")
    sl = compute_slice(cfg, source, criterion, SliceDirection.FORWARD)

    assert sl.function_name == "classify"
    assert len(sl.included_lines) > 0


def test_slice_preserves_line_numbers(parsed_sample):
    """All line numbers in a slice must be valid physical lines."""
    root, functions, source = parsed_sample
    source_line_count = len(source.decode("utf-8", errors="replace").splitlines())
    by_name = {f.name: f for f in functions}
    cfg = build_cfg(by_name["classify"])

    criterion = SliceCriterion(line=28, variable="result")
    sl = compute_slice(cfg, source, criterion, SliceDirection.BACKWARD)

    for ln in sl.included_lines:
        assert 1 <= ln <= source_line_count, f"Line {ln} out of range"


def test_slice_source_text_not_empty(parsed_sample):
    root, functions, source = parsed_sample
    by_name = {f.name: f for f in functions}
    cfg = build_cfg(by_name["classify"])

    criterion = SliceCriterion(line=28, variable="result")
    sl = compute_slice(cfg, source, criterion, SliceDirection.BACKWARD)

    assert len(sl.source_text) > 0


def test_slice_nonexistent_line(parsed_sample):
    """Slicing on a line not in any function should return empty."""
    root, functions, source = parsed_sample
    by_name = {f.name: f for f in functions}
    cfg = build_cfg(by_name["add"])

    criterion = SliceCriterion(line=9999)
    sl = compute_slice(cfg, source, criterion, SliceDirection.BACKWARD)

    assert sl.included_lines == []
    assert sl.source_text == ""


def test_def_use_pointer_deref(parsed_sample):
    """*arr = 42 should DEF *arr and arr."""
    root, functions, source = parsed_sample
    by_name = {f.name: f for f in functions}

    func = by_name["pointer_struct_test"]
    body = None
    for c in func.ast.children:
        if c.field_name == "body":
            body = c
            break

    stmts = [c for c in body.children if c.is_named]
    # Find "*arr = 42;" — it's an expression_statement
    for stmt in stmts:
        if "*arr" in stmt.text and "42" in stmt.text:
            defs, uses = _extract_def_use(stmt)
            assert any("arr" in d for d in defs), f"Expected arr in DEF, got {defs}"
            break


def test_def_use_struct_field(parsed_sample):
    """pt->x = 10 should DEF pt->x and pt."""
    root, functions, source = parsed_sample
    by_name = {f.name: f for f in functions}

    func = by_name["pointer_struct_test"]
    body = None
    for c in func.ast.children:
        if c.field_name == "body":
            body = c
            break

    stmts = [c for c in body.children if c.is_named]
    for stmt in stmts:
        if "pt->x" in stmt.text and "10" in stmt.text:
            defs, uses = _extract_def_use(stmt)
            assert any("pt" in d for d in defs), f"Expected pt in DEF, got {defs}"
            break


def test_def_use_array_subscript(parsed_sample):
    """arr[n] = pt->y should DEF arr[] and USE n, pt->y, pt."""
    root, functions, source = parsed_sample
    by_name = {f.name: f for f in functions}

    func = by_name["pointer_struct_test"]
    body = None
    for c in func.ast.children:
        if c.field_name == "body":
            body = c
            break

    stmts = [c for c in body.children if c.is_named]
    for stmt in stmts:
        if "arr[n]" in stmt.text and "pt->y" in stmt.text:
            defs, uses = _extract_def_use(stmt)
            assert any("arr" in d for d in defs), f"Expected arr in DEF, got {defs}"
            assert "n" in uses, f"Expected n in USE, got {uses}"
            break
