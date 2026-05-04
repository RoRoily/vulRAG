from __future__ import annotations

from mmrag.parsing.models import ASTNode, BasicBlock, CFG, FunctionInfo, SourceRange
from .models import SourceSinkPoint, SourceSinkRole

_DANGEROUS_APIS = frozenset({
    "malloc", "calloc", "realloc", "free",
    "memcpy", "memset", "memmove", "memcmp",
    "strcpy", "strncpy", "strcat", "strncat", "strcmp", "strncmp", "strlen",
    "sprintf", "snprintf", "printf", "fprintf", "scanf", "fscanf", "sscanf",
    "gets", "fgets", "puts", "fputs",
    "fopen", "fclose", "fread", "fwrite",
    "system", "exec", "popen", "execve", "execvp",
})


def find_dangerous_calls(func: FunctionInfo) -> list[tuple[int, str]]:
    """Scan function AST for calls to dangerous APIs. Returns [(line, api_name)]."""
    results: list[tuple[int, str]] = []

    def _walk(node: ASTNode) -> None:
        if node.node_type == "call_expression":
            for child in node.children:
                if child.field_name == "function" and child.node_type == "identifier":
                    name = child.text
                    if name.lower() in _DANGEROUS_APIS or name in _DANGEROUS_APIS:
                        results.append((node.source_range.start.line, name))
        for child in node.children:
            _walk(child)

    body = None
    for child in func.ast.children:
        if child.field_name == "body":
            body = child
            break
    if body:
        _walk(body)
    return results


def build_cfg_summary(cfg: CFG) -> str:
    """Produce a compact text summary of CFG structure for prompt context."""
    n_blocks = len(cfg.blocks)
    n_edges = len(cfg.edges)

    edge_kinds: dict[str, int] = {}
    for e in cfg.edges:
        edge_kinds[e.kind.value] = edge_kinds.get(e.kind.value, 0) + 1

    has_loops = any(k in edge_kinds for k in ("back_edge", "true_branch"))
    has_goto = "goto" in edge_kinds
    has_switch = "case" in edge_kinds or "default" in edge_kinds

    parts = [f"Blocks: {n_blocks}, Edges: {n_edges}"]
    if edge_kinds:
        kinds_str = ", ".join(f"{k}={v}" for k, v in sorted(edge_kinds.items()))
        parts.append(f"Edge types: {kinds_str}")
    if has_loops:
        parts.append("Contains loops")
    if has_goto:
        parts.append("Contains goto")
    if has_switch:
        parts.append("Contains switch/case")
    if cfg.warnings:
        parts.append(f"Parse warnings: {len(cfg.warnings)}")

    return "; ".join(parts)


def validate_source_sink_path(
    path: list[SourceSinkPoint],
    source_lines: list[str],
    cfg: CFG | None = None,
) -> list[SourceSinkPoint]:
    """Validate and clean a Source→Sink path against actual source.

    - Removes points with invalid line numbers
    - Fills in code text from source if missing
    - Optionally checks CFG reachability between consecutive points
    """
    total_lines = len(source_lines)
    validated: list[SourceSinkPoint] = []

    for point in path:
        if point.line < 1 or point.line > total_lines:
            continue
        code = point.code
        if not code.strip():
            code = source_lines[point.line - 1].strip()
        validated.append(SourceSinkPoint(
            line=point.line,
            column=point.column,
            code=code,
            description=point.description,
            role=point.role,
        ))

    if cfg and len(validated) >= 2:
        validated = _check_cfg_reachability(validated, cfg)

    return validated


def _check_cfg_reachability(
    path: list[SourceSinkPoint],
    cfg: CFG,
) -> list[SourceSinkPoint]:
    """Keep only path points that are in blocks reachable from the entry."""
    reachable_lines: set[int] = set()
    visited: set[int] = set()
    queue = [cfg.entry_block_id]

    while queue:
        bid = queue.pop(0)
        if bid in visited:
            continue
        visited.add(bid)
        block = cfg.blocks.get(bid)
        if block is None:
            continue
        for stmt in block.statements:
            sr = stmt.source_range
            for ln in range(sr.start.line, sr.end.line + 1):
                reachable_lines.add(ln)
        queue.extend(block.successors)

    return [p for p in path if p.line in reachable_lines]
