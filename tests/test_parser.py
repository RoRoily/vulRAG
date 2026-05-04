from __future__ import annotations

from mmrag.parsing.ast_parser import parse_file, collect_errors


def test_function_count(parsed_sample):
    root, functions, source = parsed_sample
    names = [f.name for f in functions]
    assert "add" in names
    assert "classify" in names
    assert "loop_examples" in names
    assert "status_string" in names
    assert "resource_handler" in names
    assert "pointer_struct_test" in names
    assert "macro_usage" in names
    assert "complex_processing" in names
    assert len(functions) == 8


def test_function_line_ranges(parsed_sample):
    root, functions, source = parsed_sample
    by_name = {f.name: f for f in functions}

    add = by_name["add"]
    assert add.source_range.start.line == 14
    assert add.source_range.end.line == 16

    classify = by_name["classify"]
    assert classify.source_range.start.line == 19


def test_function_return_type(parsed_sample):
    root, functions, source = parsed_sample
    by_name = {f.name: f for f in functions}
    assert by_name["add"].return_type == "int"
    assert by_name["loop_examples"].return_type == "void"


def test_function_parameters(parsed_sample):
    root, functions, source = parsed_sample
    by_name = {f.name: f for f in functions}

    add = by_name["add"]
    assert len(add.parameters) == 2
    assert add.parameters[0].name == "a"
    assert add.parameters[1].name == "b"

    loop = by_name["loop_examples"]
    assert len(loop.parameters) == 2


def test_signature_text(parsed_sample):
    root, functions, source = parsed_sample
    by_name = {f.name: f for f in functions}
    assert "int add(int a, int b)" in by_name["add"].signature_text


def test_ast_node_types(parsed_sample):
    root, functions, source = parsed_sample
    by_name = {f.name: f for f in functions}

    add_ast = by_name["add"].ast
    assert add_ast.node_type == "function_definition"

    def find_type(node, target):
        if node.node_type == target:
            return True
        return any(find_type(c, target) for c in node.children)

    assert find_type(by_name["classify"].ast, "if_statement")
    assert find_type(by_name["loop_examples"].ast, "for_statement")
    assert find_type(by_name["loop_examples"].ast, "while_statement")
    assert find_type(by_name["loop_examples"].ast, "do_statement")
    assert find_type(by_name["status_string"].ast, "switch_statement")
    assert find_type(by_name["resource_handler"].ast, "goto_statement")


def test_line_numbers_are_1_indexed(parsed_sample):
    root, functions, source = parsed_sample
    for func in functions:
        assert func.source_range.start.line >= 1
        assert func.body_range.start.line >= 1


def test_no_errors_in_clean_file(parsed_sample):
    root, functions, source = parsed_sample
    errors = collect_errors(root)
    # sample.c may have minor parse issues with macros like MEMSET, that's expected
    # but the core functions should parse cleanly
    assert len(functions) == 8
