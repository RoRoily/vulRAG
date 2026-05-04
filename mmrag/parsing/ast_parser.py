from __future__ import annotations

from pathlib import Path

import tree_sitter_c
import tree_sitter_cpp
from tree_sitter import Language, Parser, Node

from .models import ASTNode, FunctionInfo, ParameterInfo, SourceLocation, SourceRange

_LANG_C = Language(tree_sitter_c.language())
_LANG_CPP = Language(tree_sitter_cpp.language())

_EXT_MAP: dict[str, str] = {
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp",
    ".hpp": "cpp", ".hxx": "cpp", ".C": "cpp",
}


def create_parser(language: str) -> Parser:
    parser = Parser()
    if language == "c":
        parser.language = _LANG_C
    elif language == "cpp":
        parser.language = _LANG_CPP
    else:
        raise ValueError(f"Unsupported language: {language}")
    return parser


def detect_language(file_path: str) -> str:
    ext = Path(file_path).suffix
    lang = _EXT_MAP.get(ext)
    if lang is None:
        raise ValueError(f"Cannot detect language for extension: {ext}")
    return lang


def _make_source_range(node: Node) -> SourceRange:
    return SourceRange(
        start=SourceLocation(line=node.start_point[0] + 1, column=node.start_point[1]),
        end=SourceLocation(line=node.end_point[0] + 1, column=node.end_point[1]),
        start_byte=node.start_byte,
        end_byte=node.end_byte,
    )


def _node_to_ast(node: Node, source: bytes, field_name: str | None = None) -> ASTNode:
    children: list[ASTNode] = []
    for i, child in enumerate(node.children):
        child_field = node.field_name_for_child(i)
        children.append(_node_to_ast(child, source, child_field))
    return ASTNode(
        node_type=node.type,
        field_name=field_name,
        source_range=_make_source_range(node),
        text=source[node.start_byte:node.end_byte].decode("utf-8", errors="replace"),
        is_named=node.is_named,
        is_missing=node.is_missing,
        children=children,
    )


def _find_deepest_identifier(node: ASTNode) -> str | None:
    if node.node_type == "identifier":
        return node.text
    if node.node_type == "qualified_identifier":
        return node.text
    for child in node.children:
        if child.field_name == "declarator" or child.node_type == "identifier":
            result = _find_deepest_identifier(child)
            if result is not None:
                return result
    for child in node.children:
        result = _find_deepest_identifier(child)
        if result is not None:
            return result
    return None


def _extract_return_type(func_node: ASTNode, source: bytes) -> str:
    for child in func_node.children:
        if child.field_name == "type":
            return child.text.strip()
    return ""


def _extract_parameters(func_node: ASTNode) -> list[ParameterInfo]:
    params: list[ParameterInfo] = []
    declarator = None
    for child in func_node.children:
        if child.field_name == "declarator":
            declarator = child
            break
    if declarator is None:
        return params

    param_list = None
    queue = [declarator]
    while queue:
        n = queue.pop(0)
        if n.node_type == "parameter_list":
            param_list = n
            break
        queue.extend(n.children)
    if param_list is None:
        return params

    for child in param_list.children:
        if child.node_type in ("parameter_declaration", "optional_parameter_declaration"):
            type_text = ""
            name = ""
            for pc in child.children:
                if pc.field_name == "type":
                    type_text = pc.text.strip()
                elif pc.field_name == "declarator":
                    ident = _find_deepest_identifier(pc)
                    if ident:
                        name = ident
                    prefix = child.text[:pc.source_range.start_byte - child.source_range.start_byte]
                    if prefix.strip():
                        type_text = prefix.strip()
            if not name:
                name = _find_deepest_identifier(child) or ""
            params.append(ParameterInfo(
                name=name,
                type_text=type_text,
                source_range=child.source_range,
            ))
    return params


def extract_functions(root: ASTNode, source: bytes) -> list[FunctionInfo]:
    functions: list[FunctionInfo] = []
    queue: list[ASTNode] = [root]
    while queue:
        node = queue.pop(0)
        if node.node_type == "function_definition":
            name = ""
            declarator = None
            for child in node.children:
                if child.field_name == "declarator":
                    declarator = child
                    name = _find_deepest_identifier(child) or ""
                    break

            body_node = None
            for child in node.children:
                if child.field_name == "body":
                    body_node = child
                    break

            if body_node is None:
                continue

            return_type = _extract_return_type(node, source)
            parameters = _extract_parameters(node)
            sig_end = body_node.source_range.start_byte
            sig_start = node.source_range.start_byte
            signature_text = source[sig_start:sig_end].decode("utf-8", errors="replace").strip()

            functions.append(FunctionInfo(
                name=name,
                return_type=return_type,
                parameters=parameters,
                source_range=node.source_range,
                body_range=body_node.source_range,
                signature_text=signature_text,
                ast=node,
            ))
        else:
            queue.extend(node.children)
    return functions


def collect_errors(root: ASTNode) -> list[str]:
    errors: list[str] = []
    queue: list[ASTNode] = [root]
    while queue:
        node = queue.pop(0)
        if node.node_type in ("ERROR", "MISSING") or node.is_missing:
            sr = node.source_range
            label = "MISSING" if node.is_missing else node.node_type
            errors.append(
                f"{label} at line {sr.start.line}-{sr.end.line}: "
                f"{node.text[:80]!r}"
            )
        queue.extend(node.children)
    return errors


def parse_source(source: bytes, language: str) -> tuple[ASTNode, list[FunctionInfo]]:
    parser = create_parser(language)
    tree = parser.parse(source)
    root = _node_to_ast(tree.root_node, source)
    functions = extract_functions(root, source)
    return root, functions


def parse_file(file_path: str, language: str | None = None) -> tuple[ASTNode, list[FunctionInfo], bytes]:
    if language is None:
        language = detect_language(file_path)
    source = Path(file_path).read_bytes()
    root, functions = parse_source(source, language)
    return root, functions, source
