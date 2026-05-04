from __future__ import annotations

import re

_OPERATOR_MAP = {
    "->": " _OP_ARROW_ ",
    "::": " _OP_SCOPE_ ",
    "<<=": " _OP_LSHIFTEQ_ ",
    ">>=": " _OP_RSHIFTEQ_ ",
    "<<": " _OP_LSHIFT_ ",
    ">>": " _OP_RSHIFT_ ",
    "<=": " _OP_LE_ ",
    ">=": " _OP_GE_ ",
    "==": " _OP_EQ_ ",
    "!=": " _OP_NE_ ",
    "&&": " _OP_AND_ ",
    "||": " _OP_OR_ ",
    "+=": " _OP_ADDEQ_ ",
    "-=": " _OP_SUBEQ_ ",
    "*=": " _OP_MULEQ_ ",
    "/=": " _OP_DIVEQ_ ",
    "%=": " _OP_MODEQ_ ",
    "&=": " _OP_ANDEQ_ ",
    "|=": " _OP_OREQ_ ",
    "^=": " _OP_XOREQ_ ",
    "++": " _OP_INC_ ",
    "--": " _OP_DEC_ ",
}

_PLACEHOLDER_TO_TOKEN = {
    "_OP_ARROW_": "op_arrow",
    "_OP_SCOPE_": "op_scope",
    "_OP_LSHIFTEQ_": "op_lshifteq",
    "_OP_RSHIFTEQ_": "op_rshifteq",
    "_OP_LSHIFT_": "op_lshift",
    "_OP_RSHIFT_": "op_rshift",
    "_OP_LE_": "op_le",
    "_OP_GE_": "op_ge",
    "_OP_EQ_": "op_eq",
    "_OP_NE_": "op_ne",
    "_OP_AND_": "op_and",
    "_OP_OR_": "op_or",
    "_OP_ADDEQ_": "op_addeq",
    "_OP_SUBEQ_": "op_subeq",
    "_OP_MULEQ_": "op_muleq",
    "_OP_DIVEQ_": "op_diveq",
    "_OP_MODEQ_": "op_modeq",
    "_OP_ANDEQ_": "op_andeq",
    "_OP_OREQ_": "op_oreq",
    "_OP_XOREQ_": "op_xoreq",
    "_OP_INC_": "op_inc",
    "_OP_DEC_": "op_dec",
}

_SHORT_KEYWORDS = frozenset({"if", "do"})

_C_KEYWORDS = frozenset({
    "auto", "break", "case", "char", "const", "continue", "default", "do",
    "double", "else", "enum", "extern", "float", "for", "goto", "if",
    "int", "long", "register", "return", "short", "signed", "sizeof",
    "static", "struct", "switch", "typedef", "union", "unsigned", "void",
    "volatile", "while",
    "inline", "restrict", "bool", "true", "false", "nullptr",
    "class", "namespace", "template", "typename", "virtual", "override",
    "public", "private", "protected", "new", "delete", "throw", "try",
    "catch", "const_cast", "static_cast", "dynamic_cast", "reinterpret_cast",
    "NULL",
    "malloc", "calloc", "realloc", "free",
    "memcpy", "memset", "memmove", "memcmp",
    "strcpy", "strncpy", "strcat", "strncat", "strcmp", "strncmp", "strlen",
    "sprintf", "snprintf", "printf", "fprintf", "scanf", "fscanf", "sscanf",
    "gets", "fgets", "puts", "fputs",
    "fopen", "fclose", "fread", "fwrite",
    "system", "exec", "popen",
})

_COMMENT_RE = re.compile(
    r'//[^\n]*'
    r'|/\*[\s\S]*?\*/'
    r'|"(?:[^"\\]|\\.)*"'
    r"|'(?:[^'\\]|\\.)*'",
    re.MULTILINE,
)

_CAMEL_SPLIT_RE = re.compile(r'(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])')


def _strip_comments_and_strings(text: str) -> str:
    return _COMMENT_RE.sub(" ", text)


def _protect_operators(text: str) -> str:
    for op, placeholder in sorted(_OPERATOR_MAP.items(), key=lambda x: -len(x[0])):
        text = text.replace(op, placeholder)
    return text


def _split_identifier(token: str) -> list[str]:
    parts: list[str] = []
    for segment in token.split("_"):
        if not segment:
            continue
        camel_parts = _CAMEL_SPLIT_RE.split(segment)
        for p in camel_parts:
            if p:
                parts.append(p.lower())
    result = []
    compound = token.lower()
    if parts and compound != parts[0]:
        result.append(compound)
    result.extend(parts)
    return result


def tokenize_code(text: str) -> list[str]:
    text = _strip_comments_and_strings(text)
    text = _protect_operators(text)
    raw_tokens = re.split(r'[^a-zA-Z0-9_]+', text)
    tokens: list[str] = []
    for raw in raw_tokens:
        if not raw:
            continue
        if raw in _PLACEHOLDER_TO_TOKEN:
            tokens.append(_PLACEHOLDER_TO_TOKEN[raw])
            continue
        expanded = _split_identifier(raw)
        for t in expanded:
            if len(t) <= 1 and t not in _SHORT_KEYWORDS:
                continue
            tokens.append(t)
    return tokens


def tokenize_query(query: str) -> list[str]:
    text = _protect_operators(query)
    raw_tokens = re.split(r'[^a-zA-Z0-9_]+', text)
    tokens: list[str] = []
    for raw in raw_tokens:
        if not raw:
            continue
        if raw in _PLACEHOLDER_TO_TOKEN:
            tokens.append(_PLACEHOLDER_TO_TOKEN[raw])
            continue
        expanded = _split_identifier(raw)
        for t in expanded:
            if len(t) <= 1 and t not in _SHORT_KEYWORDS:
                continue
            tokens.append(t)
    return tokens
