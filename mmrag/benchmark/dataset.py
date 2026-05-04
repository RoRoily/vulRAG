from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from .models import AffectedLine, BenchmarkSample, VulnLabel

logger = logging.getLogger(__name__)


def load_jsonl(path: str | Path) -> list[BenchmarkSample]:
    path = Path(path)
    samples: list[BenchmarkSample] = []
    with open(path, encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                samples.append(BenchmarkSample.model_validate(data))
            except Exception as e:
                logger.warning("Skipping line %d in %s: %s", line_num, path, e)
    return samples


def save_jsonl(samples: list[BenchmarkSample], path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for sample in samples:
            f.write(sample.model_dump_json() + "\n")


def load_juliet_dir(
    root: str | Path,
    cwe_filter: list[str] | None = None,
) -> list[BenchmarkSample]:
    root = Path(root)
    if not root.is_dir():
        raise ValueError(f"Juliet root is not a directory: {root}")

    cwe_pattern = re.compile(r"CWE(\d+)")
    samples: list[BenchmarkSample] = []
    extensions = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx"}

    for cwe_dir in sorted(root.iterdir()):
        if not cwe_dir.is_dir():
            continue
        match = cwe_pattern.search(cwe_dir.name)
        if not match:
            continue

        cwe_id = f"CWE-{match.group(1)}"
        if cwe_filter and cwe_id not in cwe_filter:
            continue

        cwe_name = cwe_dir.name.replace("_", " ").strip()

        for source_file in sorted(cwe_dir.rglob("*")):
            if not source_file.is_file():
                continue
            if source_file.suffix.lower() not in extensions:
                continue

            fname_lower = source_file.name.lower()
            if "_bad" in fname_lower:
                label = VulnLabel.VULNERABLE
            elif "_good" in fname_lower:
                label = VulnLabel.SAFE
            else:
                continue

            try:
                source_code = source_file.read_text(encoding="utf-8", errors="replace")
            except OSError as e:
                logger.warning("Cannot read %s: %s", source_file, e)
                continue

            lang = "cpp" if source_file.suffix.lower() in {".cpp", ".cc", ".cxx", ".hpp", ".hxx"} else "c"

            sample_id = f"{cwe_id}_{source_file.stem}"
            samples.append(BenchmarkSample(
                sample_id=sample_id,
                file_path=str(source_file),
                language=lang,
                label=label,
                cwe_id=cwe_id,
                cwe_name=cwe_name,
                source_code=source_code,
                tags=["juliet"],
            ))

    logger.info("Loaded %d samples from Juliet directory %s", len(samples), root)
    return samples


def load_dataset(path: str | Path, format: str = "auto") -> list[BenchmarkSample]:
    path = Path(path)

    if format == "auto":
        if path.is_dir():
            format = "juliet"
        elif path.suffix.lower() in {".jsonl", ".json"}:
            format = "jsonl"
        else:
            raise ValueError(
                f"Cannot auto-detect format for {path}. "
                "Use format='jsonl' or format='juliet'."
            )

    if format == "jsonl":
        return load_jsonl(path)
    elif format == "juliet":
        return load_juliet_dir(path)
    else:
        raise ValueError(f"Unknown format: {format!r}")
