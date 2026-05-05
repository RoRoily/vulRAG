from __future__ import annotations

from collections import deque

from .models import (
    ASTNode, BasicBlock, CFG, CFGEdge, CFGEdgeKind, CFGFeatures, FunctionInfo, SourceRange,
)

_CONTROL_FLOW_TYPES = frozenset({
    "if_statement", "while_statement", "for_statement", "do_statement",
    "switch_statement", "return_statement", "goto_statement",
    "labeled_statement", "break_statement", "continue_statement",
    "compound_statement",
})

_SIMPLE_STATEMENT_TYPES = frozenset({
    "expression_statement", "declaration",
})


class _CFGBuilder:
    def __init__(self, function_name: str) -> None:
        self.function_name = function_name
        self._next_id = 0
        self.blocks: dict[int, BasicBlock] = {}
        self.edges: list[CFGEdge] = []
        self.warnings: list[str] = []
        self._label_blocks: dict[str, int] = {}
        self._pending_gotos: list[tuple[int, str]] = []
        self._break_targets: list[int] = []
        self._continue_targets: list[int] = []

    def _new_block(self, **kwargs) -> int:
        bid = self._next_id
        self._next_id += 1
        self.blocks[bid] = BasicBlock(block_id=bid, **kwargs)
        return bid

    def _add_edge(self, src: int, tgt: int, kind: CFGEdgeKind, label: str | None = None) -> None:
        self.edges.append(CFGEdge(source_id=src, target_id=tgt, kind=kind, label=label))

    def _append_stmt(self, block_id: int, node: ASTNode) -> None:
        self.blocks[block_id].statements.append(node)

    def _block_source_range(self, block_id: int) -> SourceRange | None:
        stmts = self.blocks[block_id].statements
        if not stmts:
            return None
        return SourceRange(
            start=stmts[0].source_range.start,
            end=stmts[-1].source_range.end,
            start_byte=stmts[0].source_range.start_byte,
            end_byte=stmts[-1].source_range.end_byte,
        )

    def build(self, func: FunctionInfo) -> CFG:
        entry = self._new_block(is_entry=True)
        exit_block = self._new_block(is_exit=True)
        self._exit_block = exit_block

        first_block = self._new_block()
        self._add_edge(entry, first_block, CFGEdgeKind.UNCONDITIONAL)

        body = self._get_body(func.ast)
        if body is not None:
            fallthrough = self._process_compound(body, first_block)
            if fallthrough is not None:
                self._add_edge(fallthrough, exit_block, CFGEdgeKind.UNCONDITIONAL)
        else:
            self._add_edge(first_block, exit_block, CFGEdgeKind.UNCONDITIONAL)

        self._resolve_gotos()
        self._finalize_ranges()
        self._populate_adjacency()

        return CFG(
            function_name=self.function_name,
            entry_block_id=entry,
            exit_block_id=exit_block,
            blocks=self.blocks,
            edges=self.edges,
            warnings=self.warnings,
        )

    def _get_body(self, func_node: ASTNode) -> ASTNode | None:
        for child in func_node.children:
            if child.field_name == "body" and child.node_type == "compound_statement":
                return child
        return None

    def _process_compound(self, compound: ASTNode, current: int) -> int | None:
        for child in compound.children:
            if child.node_type in ("{", "}"):
                continue
            if not child.is_named:
                continue
            result = self._process_statement(child, current)
            if result is None:
                return None
            current = result
        return current

    def _process_statement(self, node: ASTNode, current: int) -> int | None:
        ntype = node.node_type

        if ntype in _SIMPLE_STATEMENT_TYPES:
            self._append_stmt(current, node)
            return current

        if ntype == "compound_statement":
            return self._process_compound(node, current)

        if ntype == "return_statement":
            self._append_stmt(current, node)
            self._add_edge(current, self._exit_block, CFGEdgeKind.RETURN)
            return None

        if ntype == "if_statement":
            return self._process_if(node, current)

        if ntype == "while_statement":
            return self._process_while(node, current)

        if ntype == "for_statement":
            return self._process_for(node, current)

        if ntype == "do_statement":
            return self._process_do(node, current)

        if ntype == "switch_statement":
            return self._process_switch(node, current)

        if ntype == "goto_statement":
            return self._process_goto(node, current)

        if ntype == "labeled_statement":
            return self._process_labeled(node, current)

        if ntype == "break_statement":
            self._append_stmt(current, node)
            if self._break_targets:
                self._add_edge(current, self._break_targets[-1], CFGEdgeKind.BREAK)
            else:
                self.warnings.append(
                    f"break outside loop/switch at line {node.source_range.start.line}"
                )
            return None

        if ntype == "continue_statement":
            self._append_stmt(current, node)
            if self._continue_targets:
                self._add_edge(current, self._continue_targets[-1], CFGEdgeKind.CONTINUE)
            else:
                self.warnings.append(
                    f"continue outside loop at line {node.source_range.start.line}"
                )
            return None

        # Constraint A: default fallback for ERROR, MISSING, preproc_*, and any unknown node
        self._append_stmt(current, node)
        if ntype in ("ERROR", "MISSING"):
            self.warnings.append(
                f"{ntype} node at line {node.source_range.start.line} treated as opaque statement"
            )
        elif ntype not in _SIMPLE_STATEMENT_TYPES and ntype not in _CONTROL_FLOW_TYPES:
            self.warnings.append(
                f"Unrecognized node type '{ntype}' at line {node.source_range.start.line} "
                f"treated as opaque statement"
            )
        return current

    # ---- Control flow handlers ----

    def _get_child_by_field(self, node: ASTNode, field: str) -> ASTNode | None:
        for child in node.children:
            if child.field_name == field:
                return child
        return None

    def _process_if(self, node: ASTNode, current: int) -> int | None:
        join = self._new_block()

        condition = self._get_child_by_field(node, "condition")
        if condition:
            self._append_stmt(current, condition)

        consequence = self._get_child_by_field(node, "consequence")
        alternative = self._get_child_by_field(node, "alternative")

        then_block = self._new_block()
        self._add_edge(current, then_block, CFGEdgeKind.TRUE_BRANCH)

        then_exit: int | None = None
        if consequence:
            if consequence.node_type == "compound_statement":
                then_exit = self._process_compound(consequence, then_block)
            else:
                then_exit = self._process_statement(consequence, then_block)
        else:
            then_exit = then_block

        if then_exit is not None:
            self._add_edge(then_exit, join, CFGEdgeKind.UNCONDITIONAL)

        if alternative:
            # Tree-sitter wraps the else branch in an else_clause node — unwrap it
            inner = alternative
            if alternative.node_type == "else_clause":
                for c in alternative.children:
                    if c.is_named:
                        inner = c
                        break

            else_block = self._new_block()
            self._add_edge(current, else_block, CFGEdgeKind.FALSE_BRANCH)
            if inner.node_type == "if_statement":
                else_exit = self._process_if(inner, else_block)
            elif inner.node_type == "compound_statement":
                else_exit = self._process_compound(inner, else_block)
            else:
                else_exit = self._process_statement(inner, else_block)
            if else_exit is not None:
                self._add_edge(else_exit, join, CFGEdgeKind.UNCONDITIONAL)
        else:
            self._add_edge(current, join, CFGEdgeKind.FALSE_BRANCH)

        return join

    def _process_while(self, node: ASTNode, current: int) -> int | None:
        cond_block = self._new_block()
        body_block = self._new_block()
        join = self._new_block()

        self._add_edge(current, cond_block, CFGEdgeKind.UNCONDITIONAL)

        condition = self._get_child_by_field(node, "condition")
        if condition:
            self._append_stmt(cond_block, condition)

        self._add_edge(cond_block, body_block, CFGEdgeKind.TRUE_BRANCH)
        self._add_edge(cond_block, join, CFGEdgeKind.FALSE_BRANCH)

        self._break_targets.append(join)
        self._continue_targets.append(cond_block)

        body = self._get_child_by_field(node, "body")
        body_exit: int | None = body_block
        if body:
            if body.node_type == "compound_statement":
                body_exit = self._process_compound(body, body_block)
            else:
                body_exit = self._process_statement(body, body_block)

        if body_exit is not None:
            self._add_edge(body_exit, cond_block, CFGEdgeKind.BACK_EDGE)

        self._break_targets.pop()
        self._continue_targets.pop()
        return join

    def _process_for(self, node: ASTNode, current: int) -> int | None:
        initializer = self._get_child_by_field(node, "initializer")
        if initializer:
            self._append_stmt(current, initializer)

        cond_block = self._new_block()
        body_block = self._new_block()
        update_block = self._new_block()
        join = self._new_block()

        self._add_edge(current, cond_block, CFGEdgeKind.UNCONDITIONAL)

        condition = self._get_child_by_field(node, "condition")
        if condition:
            self._append_stmt(cond_block, condition)

        self._add_edge(cond_block, body_block, CFGEdgeKind.TRUE_BRANCH)
        self._add_edge(cond_block, join, CFGEdgeKind.FALSE_BRANCH)

        self._break_targets.append(join)
        self._continue_targets.append(update_block)

        body = self._get_child_by_field(node, "body")
        body_exit: int | None = body_block
        if body:
            if body.node_type == "compound_statement":
                body_exit = self._process_compound(body, body_block)
            else:
                body_exit = self._process_statement(body, body_block)

        if body_exit is not None:
            self._add_edge(body_exit, update_block, CFGEdgeKind.UNCONDITIONAL)

        update = self._get_child_by_field(node, "update")
        if update:
            self._append_stmt(update_block, update)
        self._add_edge(update_block, cond_block, CFGEdgeKind.BACK_EDGE)

        self._break_targets.pop()
        self._continue_targets.pop()
        return join

    def _process_do(self, node: ASTNode, current: int) -> int | None:
        body_block = self._new_block()
        cond_block = self._new_block()
        join = self._new_block()

        self._add_edge(current, body_block, CFGEdgeKind.UNCONDITIONAL)

        self._break_targets.append(join)
        self._continue_targets.append(cond_block)

        body = self._get_child_by_field(node, "body")
        body_exit: int | None = body_block
        if body:
            if body.node_type == "compound_statement":
                body_exit = self._process_compound(body, body_block)
            else:
                body_exit = self._process_statement(body, body_block)

        if body_exit is not None:
            self._add_edge(body_exit, cond_block, CFGEdgeKind.UNCONDITIONAL)

        condition = self._get_child_by_field(node, "condition")
        if condition:
            self._append_stmt(cond_block, condition)

        self._add_edge(cond_block, body_block, CFGEdgeKind.TRUE_BRANCH)
        self._add_edge(cond_block, join, CFGEdgeKind.FALSE_BRANCH)

        self._break_targets.pop()
        self._continue_targets.pop()
        return join

    def _process_switch(self, node: ASTNode, current: int) -> int | None:
        condition = self._get_child_by_field(node, "condition")
        if condition:
            self._append_stmt(current, condition)

        join = self._new_block()
        self._break_targets.append(join)

        body = self._get_child_by_field(node, "body")
        if body is None:
            self._break_targets.pop()
            self._add_edge(current, join, CFGEdgeKind.UNCONDITIONAL)
            return join

        case_blocks: list[tuple[int, ASTNode, CFGEdgeKind, str | None]] = []
        for child in body.children:
            if not child.is_named:
                continue
            if child.node_type == "case_statement":
                value_node = self._get_child_by_field(child, "value")
                if value_node:
                    label = value_node.text
                    cb = self._new_block()
                    case_blocks.append((cb, child, CFGEdgeKind.CASE, label))
                    self._add_edge(current, cb, CFGEdgeKind.CASE, label)
                else:
                    # default case — tree-sitter-c represents it as case_statement without value
                    cb = self._new_block()
                    case_blocks.append((cb, child, CFGEdgeKind.DEFAULT, None))
                    self._add_edge(current, cb, CFGEdgeKind.DEFAULT)
            elif child.node_type == "default_statement":
                cb = self._new_block()
                case_blocks.append((cb, child, CFGEdgeKind.DEFAULT, None))
                self._add_edge(current, cb, CFGEdgeKind.DEFAULT)

        has_default = any(k == CFGEdgeKind.DEFAULT for _, _, k, _ in case_blocks)
        if not has_default:
            self._add_edge(current, join, CFGEdgeKind.UNCONDITIONAL)

        prev_exit: int | None = None
        for i, (cb, case_node, _, _) in enumerate(case_blocks):
            if prev_exit is not None:
                self._add_edge(prev_exit, cb, CFGEdgeKind.UNCONDITIONAL)

            block_current = cb
            for child in case_node.children:
                if not child.is_named:
                    continue
                if child.node_type in ("case_statement", "default_statement"):
                    continue
                if child.field_name == "value":
                    continue
                result = self._process_statement(child, block_current)
                if result is None:
                    block_current = None
                    break
                block_current = result

            prev_exit = block_current

        if prev_exit is not None:
            self._add_edge(prev_exit, join, CFGEdgeKind.UNCONDITIONAL)

        self._break_targets.pop()
        return join

    def _process_goto(self, node: ASTNode, current: int) -> int | None:
        self._append_stmt(current, node)
        label_name = None
        for child in node.children:
            if child.node_type == "statement_identifier":
                label_name = child.text
                break
            if child.node_type == "identifier":
                label_name = child.text
                break

        if label_name is None:
            self.warnings.append(
                f"goto without label at line {node.source_range.start.line}"
            )
            return None

        if label_name in self._label_blocks:
            self._add_edge(current, self._label_blocks[label_name], CFGEdgeKind.GOTO, label_name)
        else:
            self._pending_gotos.append((current, label_name))
        return None

    def _process_labeled(self, node: ASTNode, current: int) -> int | None:
        label_name = None
        for child in node.children:
            if child.node_type == "statement_identifier":
                label_name = child.text
                break
            if child.node_type == "identifier" and child.field_name == "label":
                label_name = child.text
                break

        if label_name is None:
            self._append_stmt(current, node)
            return current

        label_block = self._new_block()
        self._label_blocks[label_name] = label_block
        self._add_edge(current, label_block, CFGEdgeKind.UNCONDITIONAL)

        inner_stmt = None
        for child in node.children:
            if child.is_named and child.node_type not in ("statement_identifier", "identifier"):
                if child.text != ":":
                    inner_stmt = child
                    break

        if inner_stmt:
            return self._process_statement(inner_stmt, label_block)
        return label_block

    # ---- Post-processing ----

    def _resolve_gotos(self) -> None:
        for src_block, label_name in self._pending_gotos:
            if label_name in self._label_blocks:
                self._add_edge(src_block, self._label_blocks[label_name], CFGEdgeKind.GOTO, label_name)
            else:
                self.warnings.append(f"Unresolved goto label: {label_name}")

    def _finalize_ranges(self) -> None:
        for block in self.blocks.values():
            block.source_range = self._block_source_range(block.block_id)

    def _populate_adjacency(self) -> None:
        for edge in self.edges:
            src = self.blocks.get(edge.source_id)
            tgt = self.blocks.get(edge.target_id)
            if src and edge.target_id not in src.successors:
                src.successors.append(edge.target_id)
            if tgt and edge.source_id not in tgt.predecessors:
                tgt.predecessors.append(edge.source_id)


def build_cfg(function: FunctionInfo) -> CFG:
    builder = _CFGBuilder(function.name)
    return builder.build(function)


def extract_cfg_features(cfg: CFG) -> CFGFeatures:
    """Extract structural graph features from a CFG for multimodal retrieval."""
    num_blocks = len(cfg.blocks)
    num_edges = len(cfg.edges)

    num_back_edges = sum(1 for e in cfg.edges if e.kind == CFGEdgeKind.BACK_EDGE)
    num_branches = sum(
        1 for e in cfg.edges
        if e.kind in (CFGEdgeKind.TRUE_BRANCH, CFGEdgeKind.FALSE_BRANCH)
    )
    num_returns = sum(1 for e in cfg.edges if e.kind == CFGEdgeKind.RETURN)

    branch_ratio = num_branches / num_edges if num_edges > 0 else 0.0

    # McCabe cyclomatic complexity: E - N + 2
    cyclomatic = max(1, num_edges - num_blocks + 2)

    # BFS from entry to find max depth (longest shortest path)
    max_depth = 0
    if cfg.entry_block_id in cfg.blocks:
        visited: dict[int, int] = {cfg.entry_block_id: 0}
        queue: deque[int] = deque([cfg.entry_block_id])
        while queue:
            bid = queue.popleft()
            depth = visited[bid]
            max_depth = max(max_depth, depth)
            for succ in cfg.blocks[bid].successors:
                if succ not in visited:
                    visited[succ] = depth + 1
                    queue.append(succ)

    return CFGFeatures(
        num_blocks=num_blocks,
        num_edges=num_edges,
        num_back_edges=num_back_edges,
        num_branches=num_branches,
        num_returns=num_returns,
        branch_ratio=round(branch_ratio, 4),
        cyclomatic_complexity=cyclomatic,
        max_block_depth=max_depth,
    )
