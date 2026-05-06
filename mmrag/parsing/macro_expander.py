from __future__ import annotations

import re
from dataclasses import dataclass, field

from .models import ASTNode


@dataclass
class MacroDef:
    name: str
    params: list[str] | None  # None = object-like, [] = nullary function-like
    body: str
    definition_line: int


@dataclass
class MacroExpansionMap:
    """Bidirectional mapping between expanded virtual lines and original physical lines."""
    # expanded_line (1-indexed) -> original physical line (1-indexed)
    expanded_to_original: dict[int, int] = field(default_factory=dict)
    # original physical line -> list of expanded lines it maps to
    original_to_expanded: dict[int, list[int]] = field(default_factory=dict)
    # expanded source text (for display / LLM context)
    expanded_lines: list[str] = field(default_factory=list)

    def translate_to_original(self, expanded_line: int) -> int:
        """Map an expanded line number back to the original physical line."""
        return self.expanded_to_original.get(expanded_line, expanded_line)

    def translate_to_expanded(self, original_line: int) -> list[int]:
        """Map an original physical line to its expanded line(s)."""
        return self.original_to_expanded.get(original_line, [original_line])


def collect_macro_defs(root: ASTNode) -> dict[str, MacroDef]:
    """Walk the AST and collect all #define macro definitions."""
    macros: dict[str, MacroDef] = {}

    def _walk(node: ASTNode) -> None:
        if node.node_type == "preproc_def":
            # Object-like: #define NAME value
            name = ""
            body = ""
            def_line = node.source_range.start.line
            for child in node.children:
                if child.node_type == "identifier" and not name:
                    name = child.text
                elif child.node_type == "preproc_arg":
                    body = child.text.strip()
            if name:
                macros[name] = MacroDef(
                    name=name,
                    params=None,
                    body=body,
                    definition_line=def_line,
                )

        elif node.node_type == "preproc_function_def":
            # Function-like: #define NAME(a, b) body
            name = ""
            params: list[str] = []
            body = ""
            def_line = node.source_range.start.line
            for child in node.children:
                if child.node_type == "identifier" and not name:
                    name = child.text
                elif child.node_type == "preproc_params":
                    for pc in child.children:
                        if pc.node_type == "identifier":
                            params.append(pc.text)
                elif child.node_type == "preproc_arg":
                    body = child.text.strip()
            if name:
                macros[name] = MacroDef(
                    name=name,
                    params=params,
                    body=body,
                    definition_line=def_line,
                )

        for child in node.children:
            _walk(child)

    _walk(root)
    return macros


def _expand_object_macro(body: str, macros: dict[str, MacroDef], depth: int = 0) -> str:
    """Recursively expand object-like macros in a body string."""
    if depth > 8:
        return body
    result = body
    for name, mdef in macros.items():
        if mdef.params is not None:
            continue
        pattern = r'\b' + re.escape(name) + r'\b'
        expanded = _expand_object_macro(mdef.body, macros, depth + 1)
        result = re.sub(pattern, expanded, result)
    return result


def _expand_function_macro(
    name: str,
    args: list[str],
    mdef: MacroDef,
    macros: dict[str, MacroDef],
    depth: int = 0,
) -> str:
    """Substitute parameters into a function-like macro body."""
    if depth > 8:
        return f"{name}({', '.join(args)})"
    body = mdef.body
    if mdef.params:
        for param, arg in zip(mdef.params, args):
            pattern = r'\b' + re.escape(param) + r'\b'
            body = re.sub(pattern, arg.strip(), body)
    # Recursively expand any macros in the result
    return _expand_line(body, macros, depth + 1)


def _split_macro_args(args_text: str) -> list[str]:
    """Split comma-separated macro arguments respecting nested parens."""
    args: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in args_text:
        if ch == '(':
            depth += 1
            current.append(ch)
        elif ch == ')':
            depth -= 1
            current.append(ch)
        elif ch == ',' and depth == 0:
            args.append(''.join(current))
            current = []
        else:
            current.append(ch)
    if current:
        args.append(''.join(current))
    return args


def _expand_line(line: str, macros: dict[str, MacroDef], depth: int = 0) -> str:
    """Expand all macro references in a single line of source text."""
    if depth > 8:
        return line

    result = line
    changed = True
    iterations = 0
    while changed and iterations < 10:
        changed = False
        iterations += 1
        for name, mdef in macros.items():
            if mdef.params is not None:
                # Function-like: look for NAME(...)
                pattern = r'\b' + re.escape(name) + r'\s*\(([^;{]*?)\)'
                match = re.search(pattern, result)
                if match:
                    args_text = match.group(1)
                    args = _split_macro_args(args_text)
                    expanded = _expand_function_macro(name, args, mdef, macros, depth + 1)
                    result = result[:match.start()] + expanded + result[match.end():]
                    changed = True
                    break
            else:
                # Object-like
                pattern = r'\b' + re.escape(name) + r'\b'
                new = re.sub(pattern, mdef.body, result)
                if new != result:
                    result = new
                    changed = True
                    break
    return result


def build_expansion_map(
    source: bytes,
    macros: dict[str, MacroDef],
) -> MacroExpansionMap:
    """
    Expand macros in source line-by-line and build the bidirectional line map.

    Lines that contain no macro references are kept as-is (1:1 mapping).
    Lines with function-like macros that expand to multiple lines get split,
    and each expanded line maps back to the original physical line.
    """
    emap = MacroExpansionMap()
    source_lines = source.decode("utf-8", errors="replace").splitlines()

    expanded_line_num = 0  # 1-indexed counter for expanded output

    for orig_idx, raw_line in enumerate(source_lines):
        orig_line = orig_idx + 1  # 1-indexed

        # Skip #define lines themselves — they don't appear in expanded output
        stripped = raw_line.strip()
        if stripped.startswith("#define") or stripped.startswith("# define"):
            continue

        expanded = _expand_line(raw_line, macros)
        expanded_parts = expanded.splitlines() if '\n' in expanded else [expanded]

        for part in expanded_parts:
            expanded_line_num += 1
            emap.expanded_lines.append(part)
            emap.expanded_to_original[expanded_line_num] = orig_line
            emap.original_to_expanded.setdefault(orig_line, []).append(expanded_line_num)

    return emap


def expand_source(
    source: bytes,
    root: ASTNode,
) -> tuple[str, MacroExpansionMap]:
    """
    High-level entry point: collect macros from AST, expand source, return
    (expanded_text, expansion_map).
    """
    macros = collect_macro_defs(root)
    emap = build_expansion_map(source, macros)
    expanded_text = "\n".join(emap.expanded_lines)
    return expanded_text, emap
