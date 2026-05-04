from __future__ import annotations

from mmrag.parsing.ast_parser import parse_file
from mmrag.parsing.cfg_builder import build_cfg
from mmrag.parsing.chunker import chunk_file
from mmrag.parsing.models import ChunkKind


def test_chunk_count(parsed_sample):
    root, functions, source = parsed_sample
    chunks = chunk_file(functions, source, "sample.c")
    assert len(chunks) > 0

    func_chunks = [c for c in chunks if c.kind == ChunkKind.FUNCTION]
    assert len(func_chunks) == len(functions)


def test_function_chunks_have_correct_names(parsed_sample):
    root, functions, source = parsed_sample
    chunks = chunk_file(functions, source, "sample.c")

    func_chunks = [c for c in chunks if c.kind == ChunkKind.FUNCTION]
    func_names = {c.function_name for c in func_chunks}
    expected = {f.name for f in functions}
    assert func_names == expected


def test_long_function_gets_block_chunks(parsed_sample):
    """complex_processing is >30 lines, should get semantic block chunks."""
    root, functions, source = parsed_sample
    chunks = chunk_file(functions, source, "sample.c", split_threshold=30)

    complex_chunks = [c for c in chunks if c.function_name == "complex_processing"]
    block_chunks = [c for c in complex_chunks if c.kind == ChunkKind.BLOCK]
    assert len(block_chunks) > 0, "Long function should produce block-level chunks"


def test_short_function_no_block_chunks(parsed_sample):
    """add() is very short, should only get a function-level chunk."""
    root, functions, source = parsed_sample
    chunks = chunk_file(functions, source, "sample.c", split_threshold=30)

    add_chunks = [c for c in chunks if c.function_name == "add"]
    assert len(add_chunks) == 1
    assert add_chunks[0].kind == ChunkKind.FUNCTION


def test_chunk_line_ranges_valid(parsed_sample):
    root, functions, source = parsed_sample
    source_line_count = len(source.decode("utf-8", errors="replace").splitlines())
    chunks = chunk_file(functions, source, "sample.c")

    for chunk in chunks:
        sr = chunk.source_range
        assert 1 <= sr.start.line <= source_line_count
        assert 1 <= sr.end.line <= source_line_count
        assert sr.start.line <= sr.end.line


def test_chunk_text_not_empty(parsed_sample):
    root, functions, source = parsed_sample
    chunks = chunk_file(functions, source, "sample.c")

    for chunk in chunks:
        assert len(chunk.text) > 0


def test_chunk_ast_node_types(parsed_sample):
    root, functions, source = parsed_sample
    chunks = chunk_file(functions, source, "sample.c")

    for chunk in chunks:
        assert isinstance(chunk.ast_node_types, list)
        if chunk.kind == ChunkKind.FUNCTION:
            assert len(chunk.ast_node_types) > 0


def test_chunk_id_format(parsed_sample):
    root, functions, source = parsed_sample
    chunks = chunk_file(functions, source, "sample.c")

    for chunk in chunks:
        assert ":" in chunk.chunk_id
        assert "-" in chunk.chunk_id
