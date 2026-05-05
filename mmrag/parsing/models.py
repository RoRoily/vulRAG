from __future__ import annotations

from enum import Enum
from pydantic import BaseModel, Field


class SourceLocation(BaseModel):
    """1-indexed physical source location."""
    line: int
    column: int


class SourceRange(BaseModel):
    start: SourceLocation
    end: SourceLocation
    start_byte: int
    end_byte: int


class ASTNode(BaseModel):
    node_type: str
    field_name: str | None = None
    source_range: SourceRange
    text: str
    is_named: bool
    is_missing: bool = False
    children: list[ASTNode] = Field(default_factory=list)


class ParameterInfo(BaseModel):
    name: str
    type_text: str
    source_range: SourceRange


class FunctionInfo(BaseModel):
    name: str
    return_type: str
    parameters: list[ParameterInfo]
    source_range: SourceRange
    body_range: SourceRange
    signature_text: str
    ast: ASTNode


class CFGEdgeKind(str, Enum):
    UNCONDITIONAL = "unconditional"
    TRUE_BRANCH = "true_branch"
    FALSE_BRANCH = "false_branch"
    CASE = "case"
    DEFAULT = "default"
    BACK_EDGE = "back_edge"
    BREAK = "break"
    CONTINUE = "continue"
    GOTO = "goto"
    RETURN = "return"


class CFGEdge(BaseModel):
    source_id: int
    target_id: int
    kind: CFGEdgeKind
    label: str | None = None


class BasicBlock(BaseModel):
    block_id: int
    statements: list[ASTNode] = Field(default_factory=list)
    source_range: SourceRange | None = None
    is_entry: bool = False
    is_exit: bool = False
    predecessors: list[int] = Field(default_factory=list)
    successors: list[int] = Field(default_factory=list)


class CFG(BaseModel):
    function_name: str
    entry_block_id: int
    exit_block_id: int
    blocks: dict[int, BasicBlock]
    edges: list[CFGEdge]
    warnings: list[str] = Field(default_factory=list)


class SliceDirection(str, Enum):
    BACKWARD = "backward"
    FORWARD = "forward"


class SliceCriterion(BaseModel):
    line: int
    variable: str | None = None


class Slice(BaseModel):
    direction: SliceDirection
    criterion: SliceCriterion
    function_name: str
    included_lines: list[int]
    statements: list[ASTNode]
    source_text: str


class ChunkKind(str, Enum):
    FUNCTION = "function"
    BLOCK = "block"
    SLICE = "slice"


class CFGFeatures(BaseModel):
    """Structural features extracted from a CFG for graph-modality retrieval."""
    num_blocks: int = 0
    num_edges: int = 0
    num_back_edges: int = 0       # loop count proxy
    num_branches: int = 0         # true/false branch edges
    num_returns: int = 0
    branch_ratio: float = 0.0     # branches / edges
    cyclomatic_complexity: int = 1  # edges - nodes + 2
    max_block_depth: int = 0      # longest path from entry (BFS depth)


class Chunk(BaseModel):
    chunk_id: str
    kind: ChunkKind
    file_path: str
    function_name: str | None = None
    source_range: SourceRange
    text: str
    line_count: int
    ast_node_types: list[str]
    cfg_features: CFGFeatures | None = None
    metadata: dict[str, str] = Field(default_factory=dict)


class ParseResult(BaseModel):
    file_path: str
    language: str
    functions: list[FunctionInfo]
    cfgs: dict[str, CFG]
    chunks: list[Chunk]
    errors: list[str] = Field(default_factory=list)
