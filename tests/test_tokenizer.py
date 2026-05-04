from __future__ import annotations

from mmrag.retrieval.tokenizer import tokenize_code, tokenize_query


def test_camel_case_split():
    tokens = tokenize_code("maxBufferSize")
    assert "max" in tokens
    assert "buffer" in tokens
    assert "size" in tokens
    assert "maxbuffersize" in tokens


def test_snake_case_split():
    tokens = tokenize_code("max_buffer_size")
    assert "max" in tokens
    assert "buffer" in tokens
    assert "size" in tokens
    assert "max_buffer_size" in tokens


def test_operators_preserved():
    tokens = tokenize_code("ptr->field")
    assert "op_arrow" in tokens
    assert "ptr" in tokens
    assert "field" in tokens


def test_scope_resolution():
    tokens = tokenize_code("std::vector")
    assert "op_scope" in tokens
    assert "std" in tokens
    assert "vector" in tokens


def test_comments_stripped():
    tokens = tokenize_code("x = 1; // this is a comment")
    assert "comment" not in tokens
    assert "this" not in tokens


def test_block_comments_stripped():
    tokens = tokenize_code("x = 1; /* block comment */ y = 2;")
    assert "block" not in tokens
    assert "comment" not in tokens


def test_string_literals_stripped():
    tokens = tokenize_code('printf("hello world");')
    assert "hello" not in tokens
    assert "world" not in tokens
    assert "printf" in tokens


def test_keywords_preserved():
    tokens = tokenize_code("if (x) return 0;")
    assert "if" in tokens
    assert "return" in tokens


def test_dangerous_apis():
    tokens = tokenize_code("strcpy(dst, src); malloc(size); free(ptr);")
    assert "strcpy" in tokens
    assert "malloc" in tokens
    assert "free" in tokens


def test_empty_input():
    assert tokenize_code("") == []


def test_single_chars_filtered():
    tokens = tokenize_code("a = b + c;")
    assert "a" not in tokens
    assert "b" not in tokens
    assert "c" not in tokens


def test_query_tokenizer():
    tokens = tokenize_query("malloc free buffer overflow")
    assert "malloc" in tokens
    assert "free" in tokens
    assert "buffer" in tokens
    assert "overflow" in tokens


def test_query_with_operators():
    tokens = tokenize_query("ptr->field == NULL")
    assert "op_arrow" in tokens
    assert "ptr" in tokens
    assert "op_eq" in tokens
    assert "null" in tokens
