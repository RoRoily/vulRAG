from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from mmrag.benchmark.dataset import load_jsonl
from mmrag.benchmark.models import VulnLabel
from mmrag.finetune.models import FinetuneConfig, FinetuneResult, Triplet
from mmrag.finetune.triplet_gen import (
    _build_anchor_text,
    _find_hard_negatives,
    generate_triplets_from_benchmark,
    load_triplets,
    save_triplets,
)


@pytest.fixture
def benchmark_samples() -> list:
    path = Path(__file__).parent / "fixtures" / "benchmark_sample.jsonl"
    return load_jsonl(path)


class TestModels:
    def test_triplet_roundtrip(self):
        t = Triplet(
            anchor="CWE-122 buffer overflow",
            positive="void foo() { malloc(10); }",
            negative="void bar() { int x = 0; }",
            anchor_id="a1",
            positive_id="p1",
            negative_id="n1",
        )
        data = json.loads(t.model_dump_json())
        restored = Triplet.model_validate(data)
        assert restored.anchor == t.anchor
        assert restored.positive_id == "p1"

    def test_finetune_config_defaults(self):
        config = FinetuneConfig(base_model_path="/fake/model")
        assert config.batch_size == 16
        assert config.epochs == 3
        assert config.fp16 is True
        assert config.learning_rate == 2e-5
        assert config.device == "auto"

    def test_finetune_result(self):
        result = FinetuneResult(
            output_dir="/out",
            num_triplets=100,
            epochs_completed=3,
            final_loss=0.5,
            eval_metrics={"triplet_accuracy": 0.85},
        )
        assert result.eval_metrics["triplet_accuracy"] == 0.85


class TestTripletGeneration:
    def test_generate_triplets(self, benchmark_samples):
        triplets = generate_triplets_from_benchmark(
            benchmark_samples, num_hard_negatives=1, seed=42
        )
        assert len(triplets) > 0
        for t in triplets:
            assert t.anchor != ""
            assert t.positive != ""
            assert t.negative != ""

    def test_generate_triplets_no_safe_samples(self):
        from mmrag.benchmark.models import BenchmarkSample

        vuln_only = [
            BenchmarkSample(
                sample_id="v1",
                label=VulnLabel.VULNERABLE,
                source_code="void foo() { malloc(10); }",
            ),
        ]
        triplets = generate_triplets_from_benchmark(vuln_only)
        assert triplets == []

    def test_build_anchor_text(self):
        from mmrag.benchmark.models import BenchmarkSample

        sample = BenchmarkSample(
            sample_id="t1",
            label=VulnLabel.VULNERABLE,
            cwe_id="CWE-122",
            cwe_name="Heap-based Buffer Overflow",
            description="Overflow via malloc",
        )
        text = _build_anchor_text(sample)
        assert "CWE-122" in text
        assert "Overflow via malloc" in text

    def test_build_anchor_text_no_cwe(self):
        from mmrag.benchmark.models import BenchmarkSample

        sample = BenchmarkSample(
            sample_id="t2",
            label=VulnLabel.VULNERABLE,
            description="Some vulnerability",
        )
        text = _build_anchor_text(sample)
        assert "Some vulnerability" in text

    def test_build_anchor_text_empty(self):
        from mmrag.benchmark.models import BenchmarkSample

        sample = BenchmarkSample(
            sample_id="t3",
            label=VulnLabel.VULNERABLE,
        )
        text = _build_anchor_text(sample)
        assert len(text) > 0

    def test_find_hard_negatives_same_cwe_priority(self):
        import numpy as np
        from mmrag.benchmark.models import BenchmarkSample
        from mmrag.parsing.models import (
            Chunk, ChunkKind, SourceRange, SourceLocation,
        )

        dummy_range = SourceRange(
            start=SourceLocation(line=1, column=0),
            end=SourceLocation(line=5, column=0),
            start_byte=0, end_byte=50,
        )

        pos_sample = BenchmarkSample(
            sample_id="v1", label=VulnLabel.VULNERABLE, cwe_id="CWE-122",
        )
        pos_chunk = Chunk(
            chunk_id="pos", kind=ChunkKind.FUNCTION, file_path="a.c",
            source_range=dummy_range, text="void foo() {}", line_count=5,
            ast_node_types=["call_expression"],
        )

        same_cwe_chunk = Chunk(
            chunk_id="same_cwe", kind=ChunkKind.FUNCTION, file_path="b.c",
            source_range=dummy_range, text="void bar() {}", line_count=5,
            ast_node_types=["declaration"],
        )
        other_chunk = Chunk(
            chunk_id="other", kind=ChunkKind.FUNCTION, file_path="c.c",
            source_range=dummy_range, text="void baz() {}", line_count=5,
            ast_node_types=["return_statement"],
        )

        safe_chunks = [
            (BenchmarkSample(sample_id="s1", label=VulnLabel.SAFE, cwe_id="CWE-122"), same_cwe_chunk),
            (BenchmarkSample(sample_id="s2", label=VulnLabel.SAFE, cwe_id="CWE-78"), other_chunk),
        ]

        rng = np.random.RandomState(42)
        negatives = _find_hard_negatives(pos_sample, pos_chunk, safe_chunks, 1, rng)
        assert len(negatives) == 1
        assert negatives[0].chunk_id == "same_cwe"


class TestTripletPersistence:
    def test_save_load_roundtrip(self):
        triplets = [
            Triplet(anchor="a1", positive="p1", negative="n1"),
            Triplet(anchor="a2", positive="p2", negative="n2"),
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "triplets.jsonl"
            save_triplets(triplets, path)
            loaded = load_triplets(path)
            assert len(loaded) == 2
            assert loaded[0].anchor == "a1"
            assert loaded[1].negative == "n2"


class TestTrainer:
    def test_finetuner_offline_env(self):
        import os
        from mmrag.finetune.trainer import EmbeddingFinetuner

        config = FinetuneConfig(base_model_path="/fake/model")
        finetuner = EmbeddingFinetuner(config)
        try:
            finetuner._load_base_model()
        except Exception:
            pass
        assert os.environ.get("HF_HUB_OFFLINE") == "1"
        assert os.environ.get("TRANSFORMERS_OFFLINE") == "1"
