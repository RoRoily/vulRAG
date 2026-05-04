from __future__ import annotations

from .models import (
    ASTNode, BasicBlock, CFG, Slice, SliceCriterion, SliceDirection, SourceRange,
)


def _normalize_access_path(node: ASTNode) -> tuple[str, set[str]]:
    """Build a normalized access path from an lvalue AST node.

    Returns (path_string, set_of_index_vars_used).
    E.g. for `ptr->arr[i].x`:  ("ptr->arr[].x", {"i"})
    """
    index_vars: set[str] = set()

    def _walk(n: ASTNode) -> str:
        if n.node_type == "identifier":
            return n.text

        if n.node_type == "pointer_expression":
            for c in n.children:
                if c.node_type != "*":
                    inner = _walk(c)
                    return f"*{inner}"
            return n.text

        if n.node_type == "field_expression":
            obj = None
            field = None
            op = "."
            for c in n.children:
                if c.field_name == "argument":
                    obj = _walk(c)
                elif c.field_name == "field":
                    field = c.text
                elif c.node_type in (".", "->"):
                    op = c.text if not c.is_named else c.node_type
                elif c.text in (".", "->"):
                    op = c.text
            if obj and field:
                return f"{obj}{op}{field}"
            return n.text

        if n.node_type == "subscript_expression":
            arr = None
            idx = None
            for c in n.children:
                if c.field_name == "argument":
                    arr = _walk(c)
                elif c.field_name == "index":
                    idx = c
            if idx:
                idx_ids = _collect_identifiers(idx)
                index_vars.update(idx_ids)
            if arr:
                return f"{arr}[]"
            return n.text

        if n.node_type == "parenthesized_expression":
            for c in n.children:
                if c.is_named:
                    return _walk(c)

        return n.text

    path = _walk(node)
    return path, index_vars


def _collect_identifiers(node: ASTNode) -> set[str]:
    ids: set[str] = set()
    if node.node_type == "identifier":
        ids.add(node.text)
    for c in node.children:
        ids.update(_collect_identifiers(c))
    return ids


def _base_var(path: str) -> str:
    """Extract the root variable from a normalized path.
    E.g. "*ptr" -> "ptr", "obj.field" -> "obj", "ptr->arr[].x" -> "ptr"
    """
    s = path.lstrip("*")
    for sep in ("->", ".", "["):
        idx = s.find(sep)
        if idx != -1:
            s = s[:idx]
    return s


def _is_callee(node: ASTNode) -> bool:
    return node.field_name == "function"


def _is_type_context(node: ASTNode) -> bool:
    return node.node_type in (
        "type_identifier", "primitive_type", "sized_type_specifier",
        "type_descriptor", "struct_specifier", "enum_specifier",
        "union_specifier",
    )


def _extract_def_use(statement: ASTNode) -> tuple[set[str], set[str]]:
    """Compute DEF and USE sets for a single statement.

    Returns (def_set, use_set) with normalized path tokens.
    For ERROR/MISSING nodes, returns empty sets (Constraint A).
    """
    defs: set[str] = set()
    uses: set[str] = set()

    if statement.node_type in ("ERROR", "MISSING"):
        return defs, uses

    def _process(node: ASTNode, in_lhs: bool = False) -> None:
        if node.node_type == "assignment_expression":
            lhs = None
            rhs = None
            for c in node.children:
                if c.field_name == "left":
                    lhs = c
                elif c.field_name == "right":
                    rhs = c
            if lhs:
                path, idx_vars = _normalize_access_path(lhs)
                defs.add(path)
                base = _base_var(path)
                if base != path:
                    defs.add(base)
                uses.update(idx_vars)
                if path.startswith("*"):
                    uses.add(_base_var(path))
            if rhs:
                _process(rhs, in_lhs=False)
            return

        if node.node_type in ("update_expression", "augmented_assignment_expression"):
            for c in node.children:
                if c.node_type == "identifier":
                    defs.add(c.text)
                    uses.add(c.text)
                elif c.is_named:
                    path, idx_vars = _normalize_access_path(c)
                    defs.add(path)
                    uses.add(path)
                    uses.update(idx_vars)
            return

        if node.node_type == "declaration":
            for c in node.children:
                if c.node_type == "init_declarator":
                    decl = None
                    value = None
                    for ic in c.children:
                        if ic.field_name == "declarator":
                            decl = ic
                        elif ic.field_name == "value":
                            value = ic
                    if decl:
                        ident = _find_decl_identifier(decl)
                        if ident:
                            defs.add(ident)
                    if value:
                        _process(value, in_lhs=False)
                elif c.field_name == "declarator":
                    ident = _find_decl_identifier(c)
                    if ident:
                        defs.add(ident)
            return

        if node.node_type == "call_expression":
            for c in node.children:
                if _is_callee(c):
                    continue
                if c.node_type == "argument_list":
                    for arg in c.children:
                        if arg.is_named:
                            _process(arg, in_lhs=False)
                else:
                    _process(c, in_lhs=False)
            return

        if node.node_type == "identifier" and not in_lhs:
            if not _is_callee(node) and not _is_type_context(node):
                uses.add(node.text)
            return

        if node.node_type in ("field_expression", "subscript_expression", "pointer_expression"):
            if not in_lhs:
                path, idx_vars = _normalize_access_path(node)
                uses.add(path)
                base = _base_var(path)
                if base != path:
                    uses.add(base)
                uses.update(idx_vars)
            return

        for c in node.children:
            if _is_type_context(c):
                continue
            _process(c, in_lhs=in_lhs)

    _process(statement)
    return defs, uses


def _find_decl_identifier(node: ASTNode) -> str | None:
    if node.node_type == "identifier":
        return node.text
    for c in node.children:
        if c.field_name == "declarator" or c.node_type == "identifier":
            result = _find_decl_identifier(c)
            if result:
                return result
    for c in node.children:
        result = _find_decl_identifier(c)
        if result:
            return result
    return None


def _vars_match(criterion_var: str, candidate: str) -> bool:
    """Prefix matching: "ptr" matches "ptr", "ptr->field", "ptr->other", etc."""
    if criterion_var == candidate:
        return True
    base_crit = _base_var(criterion_var)
    base_cand = _base_var(candidate)
    if base_crit == base_cand:
        return True
    if candidate.startswith(criterion_var) and len(candidate) > len(criterion_var):
        next_char = candidate[len(criterion_var)]
        if next_char in (".", "-", "["):
            return True
    if criterion_var.startswith(candidate) and len(criterion_var) > len(candidate):
        next_char = criterion_var[len(candidate)]
        if next_char in (".", "-", "["):
            return True
    return False


def _find_statement_at_line(cfg: CFG, line: int) -> tuple[int, int] | None:
    """Find (block_id, statement_index) for the statement covering the given line."""
    for block in cfg.blocks.values():
        for i, stmt in enumerate(block.statements):
            sr = stmt.source_range
            if sr.start.line <= line <= sr.end.line:
                return block.block_id, i
    return None


def _get_all_vars_in_statement(stmt: ASTNode) -> set[str]:
    defs, uses = _extract_def_use(stmt)
    return defs | uses


def compute_slice(
    cfg: CFG,
    source: bytes,
    criterion: SliceCriterion,
    direction: SliceDirection = SliceDirection.BACKWARD,
) -> Slice:
    location = _find_statement_at_line(cfg, criterion.line)
    if location is None:
        return Slice(
            direction=direction,
            criterion=criterion,
            function_name=cfg.function_name,
            included_lines=[],
            statements=[],
            source_text="",
        )

    block_id, stmt_idx = location
    seed_stmt = cfg.blocks[block_id].statements[stmt_idx]

    if criterion.variable:
        seed_vars = {criterion.variable}
    else:
        seed_defs, seed_uses = _extract_def_use(seed_stmt)
        seed_vars = seed_uses if direction == SliceDirection.BACKWARD else seed_defs

    relevant_stmts: set[tuple[int, int]] = {(block_id, stmt_idx)}

    if direction == SliceDirection.BACKWARD:
        _backward_slice(cfg, block_id, stmt_idx, seed_vars, relevant_stmts)
    else:
        _forward_slice(cfg, block_id, stmt_idx, seed_vars, relevant_stmts)

    all_stmts: list[ASTNode] = []
    all_lines: set[int] = set()
    for bid, sidx in sorted(relevant_stmts):
        block = cfg.blocks.get(bid)
        if block and sidx < len(block.statements):
            stmt = block.statements[sidx]
            all_stmts.append(stmt)
            sr = stmt.source_range
            for ln in range(sr.start.line, sr.end.line + 1):
                all_lines.add(ln)

    sorted_lines = sorted(all_lines)
    source_lines = source.decode("utf-8", errors="replace").splitlines(keepends=True)
    slice_text_parts: list[str] = []
    for ln in sorted_lines:
        if 1 <= ln <= len(source_lines):
            slice_text_parts.append(source_lines[ln - 1])
    slice_text = "".join(slice_text_parts)

    return Slice(
        direction=direction,
        criterion=criterion,
        function_name=cfg.function_name,
        included_lines=sorted_lines,
        statements=all_stmts,
        source_text=slice_text,
    )


def _propagate_to_predecessors(
    cfg: CFG,
    block: BasicBlock,
    var: str,
    worklist: list,
    seen: set[int],
) -> None:
    """Recursively traverse empty predecessor blocks until we find one with statements."""
    for pred_id in block.predecessors:
        if pred_id in seen:
            continue
        seen.add(pred_id)
        pred = cfg.blocks.get(pred_id)
        if pred is None:
            continue
        if pred.statements:
            worklist.append((pred_id, len(pred.statements) - 1, var, False))
        else:
            _propagate_to_predecessors(cfg, pred, var, worklist, seen)


def _propagate_to_successors(
    cfg: CFG,
    block: BasicBlock,
    var: str,
    worklist: list[tuple[int, int, str]],
    seen: set[int],
) -> None:
    """Recursively traverse empty successor blocks until we find one with statements."""
    for succ_id in block.successors:
        if succ_id in seen:
            continue
        seen.add(succ_id)
        succ = cfg.blocks.get(succ_id)
        if succ is None or succ.is_exit:
            continue
        if succ.statements:
            worklist.append((succ_id, -1, var))
        else:
            _propagate_to_successors(cfg, succ, var, worklist, seen)


def _backward_slice(
    cfg: CFG,
    start_block: int,
    start_idx: int,
    seed_vars: set[str],
    relevant: set[tuple[int, int]],
) -> None:
    # Worklist items: (block_id, start_search_idx, var, is_seed)
    # is_seed=True means we skip the statement at start_search_idx (it's the criterion itself)
    worklist: list[tuple[int, int, str, bool]] = []
    for v in seed_vars:
        worklist.append((start_block, start_idx, v, True))

    visited: set[tuple[int, int, str]] = set()

    while worklist:
        bid, sidx, var, is_seed = worklist.pop()
        if (bid, sidx, var) in visited:
            continue
        visited.add((bid, sidx, var))

        block = cfg.blocks.get(bid)
        if block is None:
            continue

        found = False
        idx = sidx if not is_seed else sidx - 1
        while idx >= 0:
            stmt = block.statements[idx]
            defs, uses = _extract_def_use(stmt)
            if _any_match(var, defs):
                if (bid, idx) not in relevant:
                    relevant.add((bid, idx))
                    for u in uses:
                        worklist.append((bid, idx, u, False))
                found = True
                break
            idx -= 1

        if not found:
            _propagate_to_predecessors(cfg, block, var, worklist, set())


def _forward_slice(
    cfg: CFG,
    start_block: int,
    start_idx: int,
    seed_vars: set[str],
    relevant: set[tuple[int, int]],
) -> None:
    worklist: list[tuple[int, int, str]] = []
    for v in seed_vars:
        worklist.append((start_block, start_idx, v))

    visited: set[tuple[int, int, str]] = set()

    while worklist:
        bid, sidx, var = worklist.pop()
        if (bid, sidx, var) in visited:
            continue
        visited.add((bid, sidx, var))

        block = cfg.blocks.get(bid)
        if block is None:
            continue

        idx = sidx + 1
        while idx < len(block.statements):
            stmt = block.statements[idx]
            defs, uses = _extract_def_use(stmt)
            if _any_match(var, uses):
                if (bid, idx) not in relevant:
                    relevant.add((bid, idx))
                    for d in defs:
                        worklist.append((bid, idx, d))
            if _any_match(var, defs):
                break
            idx += 1

        if idx >= len(block.statements):
            _propagate_to_successors(cfg, block, var, worklist, set())


def _any_match(var: str, var_set: set[str]) -> bool:
    for v in var_set:
        if _vars_match(var, v):
            return True
    return False
