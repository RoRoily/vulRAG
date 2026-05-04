from __future__ import annotations

import pytest
from pathlib import Path

from mmrag.parsing.ast_parser import parse_file, parse_source, collect_errors
from mmrag.parsing.models import ASTNode, FunctionInfo


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_c(fixtures_dir) -> Path:
    return fixtures_dir / "sample.c"


@pytest.fixture
def sample_broken_c(fixtures_dir) -> Path:
    return fixtures_dir / "sample_broken.c"


@pytest.fixture
def parsed_sample(sample_c):
    root, functions, source = parse_file(str(sample_c))
    return root, functions, source
