from __future__ import annotations

from .cfg_builder import extract_cfg_features
from .models import (
    ASTNode, CFG, CFGFeatures, Chunk, ChunkKind, FunctionInfo, SourceRange, SourceLocation,
)

_COMPOUND_TYPES = frozenset({
    "if_statement", "for_statement", "while_statement",
    "do_statement", "switch_statement",
})


def _collect_node_types(node: ASTNode) -> list[str]:
    types: set[str] = set()

    def _walk(n: ASTNode) -> None:
        if n.is_named:
            types.add(n.node_type)
        for c in n.children:
            _walk(c)

    _walk(node)
    return sorted(types)


def _has_error_nodes(node: ASTNode) -> bool:
    if node.node_type in ("ERROR", "MISSING"):
        return True
    return any(_has_error_nodes(c) for c in node.children)


def _text_from_source(source: bytes, sr: SourceRange) -> str:
    return source[sr.start_byte:sr.end_byte].decode("utf-8", errors="replace")


def _make_chunk_id(file_path: str, func_name: str | None, start_line: int, end_line: int) -> str:
    fn = func_name or "<global>"
    return f"{file_path}:{fn}:{start_line}-{end_line}"


def _make_function_chunk(
    func: FunctionInfo,
    source: bytes,
    file_path: str,
    cfg: CFG | None = None,
) -> Chunk:
    sr = func.source_range
    text = _text_from_source(source, sr)
    node_types = _collect_node_types(func.ast)
    metadata: dict[str, str] = {}
    if _has_error_nodes(func.ast):
        metadata["has_errors"] = "true"
    cfg_features: CFGFeatures | None = extract_cfg_features(cfg) if cfg is not None else None
    return Chunk(
        chunk_id=_make_chunk_id(file_path, func.name, sr.start.line, sr.end.line),
        kind=ChunkKind.FUNCTION,
        file_path=file_path,
        function_name=func.name,
        source_range=sr,
        text=text,
        line_count=sr.end.line - sr.start.line + 1,
        ast_node_types=node_types,
        cfg_features=cfg_features,
        metadata=metadata,
    )


def _group_source_range(nodes: list[ASTNode]) -> SourceRange:
    first = nodes[0].source_range
    last = nodes[-1].source_range
    return SourceRange(
        start=first.start,
        end=last.end,
        start_byte=first.start_byte,
        end_byte=last.end_byte,
    )


def _make_block_chunk(
    nodes: list[ASTNode],
    func: FunctionInfo,
    source: bytes,
    file_path: str,
) -> Chunk:
    sr = _group_source_range(nodes)
    text = _text_from_source(source, sr)

    all_types: set[str] = set()
    has_errors = False
    for n in nodes:
        all_types.update(_collect_node_types(n))
        if not has_errors and _has_error_nodes(n):
            has_errors = True

    metadata: dict[str, str] = {}
    if has_errors:
        metadata["has_errors"] = "true"
    metadata["context"] = func.signature_text

    return Chunk(
        chunk_id=_make_chunk_id(file_path, func.name, sr.start.line, sr.end.line),
        kind=ChunkKind.BLOCK,
        file_path=file_path,
        function_name=func.name,
        source_range=sr,
        text=text,
        line_count=sr.end.line - sr.start.line + 1,
        ast_node_types=sorted(all_types),
        metadata=metadata,
    )


def _get_body_children(func: FunctionInfo) -> list[ASTNode]:
    """Get the named children of the function body (compound_statement)."""
    for child in func.ast.children:
        if child.field_name == "body" and child.node_type == "compound_statement":
            return [c for c in child.children if c.is_named]
    return []


def _chunk_function(
    func: FunctionInfo,
    source: bytes,
    file_path: str,
    split_threshold: int,
    max_simple_group: int,
    cfg: CFG | None = None,
) -> list[Chunk]:
    chunks: list[Chunk] = []
    chunks.append(_make_function_chunk(func, source, file_path, cfg=cfg))

    func_lines = func.source_range.end.line - func.source_range.start.line + 1
    if func_lines <= split_threshold:
        return chunks

    body_children = _get_body_children(func)
    if not body_children:
        return chunks

    current_group: list[ASTNode] = []

    def _flush_group() -> None:
        nonlocal current_group
        if current_group:
            chunks.append(_make_block_chunk(current_group, func, source, file_path))
            current_group = []

    for child in body_children:
        if child.node_type in _COMPOUND_TYPES:
            _flush_group()
            chunks.append(_make_block_chunk([child], func, source, file_path))
        else:
            current_group.append(child)
            if current_group:
                group_lines = (
                    current_group[-1].source_range.end.line
                    - current_group[0].source_range.start.line + 1
                )
                if group_lines >= max_simple_group:
                    _flush_group()

    _flush_group()
    return chunks


def chunk_file(
    functions: list[FunctionInfo],
    source: bytes,
    file_path: str,
    split_threshold: int = 30,
    max_simple_group: int = 15,
    cfgs: dict[str, CFG] | None = None,
) -> list[Chunk]:
    chunks: list[Chunk] = []
    for func in functions:
        cfg = cfgs.get(func.name) if cfgs else None
        chunks.extend(
            _chunk_function(func, source, file_path, split_threshold, max_simple_group, cfg=cfg)
        )
    return chunks
