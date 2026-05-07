"""
benchmark_tables.py — 将 results/all_tables.json 格式化为 LaTeX 表格

用法:
  python scripts/benchmark_tables.py                        # 读取 results/all_tables.json
  python scripts/benchmark_tables.py --input results/all_tables.json
  python scripts/benchmark_tables.py --dry-run              # 使用内置模拟数据
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def _pct(v: float) -> str:
    """Format a float as a percentage string with two decimal places."""
    return f"{v:.2f}\\%"


def _bold(s: str) -> str:
    return f"\\textbf{{{s}}}"


def _best_row_indices(rows: list, col_indices: list[int], higher_is_better: list[bool]) -> dict[int, int]:
    """Return {col_index: row_index_of_best_value}."""
    best: dict[int, int] = {}
    for ci, hib in zip(col_indices, higher_is_better):
        vals = [row[ci] for row in rows]
        best[ci] = vals.index(max(vals) if hib else min(vals))
    return best


def _latex_table(
    caption: str,
    label: str,
    header: list[str],
    rows: list[tuple],
    col_fmt: str,
    pct_cols: list[int],
    best_cols: list[int],
    higher_is_better: list[bool],
    notes: str = "",
) -> str:
    best = _best_row_indices(rows, best_cols, higher_is_better)

    lines: list[str] = []
    lines.append(r"\begin{table}[htbp]")
    lines.append(r"  \centering")
    lines.append(f"  \\caption{{{caption}}}")
    lines.append(f"  \\label{{{label}}}")
    lines.append(f"  \\begin{{tabular}}{{{col_fmt}}}")
    lines.append(r"    \toprule")

    # Header
    lines.append("    " + " & ".join(f"\\textbf{{{h}}}" for h in header) + r" \\")
    lines.append(r"    \midrule")

    # Data rows
    for ri, row in enumerate(rows):
        cells: list[str] = []
        for ci, val in enumerate(row):
            if ci in pct_cols:
                cell = _pct(float(val))
            else:
                cell = str(val)
            if ci in best and best[ci] == ri:
                cell = _bold(cell)
            cells.append(cell)
        lines.append("    " + " & ".join(cells) + r" \\")

    lines.append(r"    \bottomrule")
    lines.append(r"  \end{tabular}")
    if notes:
        lines.append(f"  \\begin{{tablenotes}}\\small\\item {notes}\\end{{tablenotes}}")
    lines.append(r"\end{table}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Table 6.1
# ---------------------------------------------------------------------------

def table61(rows: list) -> str:
    return _latex_table(
        caption="不同检索策略性能对比",
        label="tab:retrieval-strategy",
        header=["检索策略", "Recall@5", "Recall@10", "MRR", "Precision@10"],
        rows=rows,
        col_fmt="lrrrr",
        pct_cols=[1, 2, 3, 4],
        best_cols=[1, 2, 3, 4],
        higher_is_better=[True, True, True, True],
        notes="所有指标均以百分比表示，粗体为各列最优值。",
    )


# ---------------------------------------------------------------------------
# Table 6.2
# ---------------------------------------------------------------------------

def table62(rows: list) -> str:
    return _latex_table(
        caption="RRF 参数 $k$ 消融实验",
        label="tab:rrf-ablation",
        header=["$k$ 值", "Recall@10", "MRR"],
        rows=rows,
        col_fmt="lrr",
        pct_cols=[1, 2],
        best_cols=[1, 2],
        higher_is_better=[True, True],
        notes="固定检索策略为 BM25+嵌入二路 RRF，仅改变 $k$ 值。",
    )


# ---------------------------------------------------------------------------
# Table 6.3
# ---------------------------------------------------------------------------

def table63(rows: list) -> str:
    return _latex_table(
        caption="与基线方法漏洞检测性能对比",
        label="tab:baseline-comparison",
        header=["方法", "Precision", "Recall", "F1", "FPR"],
        rows=rows,
        col_fmt="lrrrr",
        pct_cols=[1, 2, 3, 4],
        best_cols=[1, 2, 3, 4],
        higher_is_better=[True, True, True, False],
        notes="FPR（假阳性率）越低越好，粗体为各列最优值。",
    )


# ---------------------------------------------------------------------------
# Table 6.4
# ---------------------------------------------------------------------------

def table64(rows: list) -> str:
    return _latex_table(
        caption="Actor-Critic 推理框架消融实验",
        label="tab:actor-critic-ablation",
        header=["推理配置", "F1", "FPR", "幻觉率"],
        rows=rows,
        col_fmt="lrrr",
        pct_cols=[1, 2, 3],
        best_cols=[1, 2, 3],
        higher_is_better=[True, False, False],
        notes="幻觉率为输出无法解析为合法 JSON 的样本比例，越低越好。",
    )


# ---------------------------------------------------------------------------
# Table 6.5
# ---------------------------------------------------------------------------

def table65(rows: list) -> str:
    # rows: (cwe, desc, f1_no, f1_with, delta)
    # delta can be negative — bold the highest delta
    return _latex_table(
        caption="图模态对各 CWE 类别检测性能的贡献",
        label="tab:graph-cwe-contribution",
        header=["CWE 类别", "漏洞描述", "无图模态 F1", "有图模态 F1", "提升 $\\Delta$"],
        rows=rows,
        col_fmt="llrrr",
        pct_cols=[2, 3, 4],
        best_cols=[4],
        higher_is_better=[True],
        notes="$\\Delta = $ 有图模态 F1 $-$ 无图模态 F1，粗体为提升最大的类别。",
    )


# ---------------------------------------------------------------------------
# Combined output
# ---------------------------------------------------------------------------

PREAMBLE = r"""\usepackage{booktabs}
% 以下表格可直接粘贴至 chapter6-implement.tex
% 需要在导言区引入 booktabs 宏包
"""


def generate_all_latex(data: dict) -> str:
    parts: list[str] = [PREAMBLE, "% ============================================================"]

    table_funcs = [
        ("table61", table61, "表 6.1：不同检索策略性能对比"),
        ("table62", table62, "表 6.2：RRF 参数 k 消融实验"),
        ("table63", table63, "表 6.3：与基线方法漏洞检测性能对比"),
        ("table64", table64, "表 6.4：Actor-Critic 消融实验"),
        ("table65", table65, "表 6.5：图模态对各 CWE 类别检测性能的贡献"),
    ]

    for key, fn, comment in table_funcs:
        rows = data.get(key)
        if not rows:
            parts.append(f"% {comment} — 数据缺失，跳过")
            continue
        parts.append(f"\n% {comment}")
        parts.append(fn(rows))

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Dry-run data (mirrors run_benchmark.py)
# ---------------------------------------------------------------------------

DRY_RUN = {
    "table61": [
        ("BM25单路",              62.14, 71.38, 55.23, 18.47),
        ("嵌入单路",              65.82, 74.61, 58.91, 19.73),
        ("BM25+嵌入二路RRF",      72.35, 80.17, 64.48, 22.16),
        ("BM25+嵌入+CFG三路RRF",  76.89, 84.52, 68.73, 24.31),
    ],
    "table62": [
        (1,   77.14, 61.05),
        (10,  81.93, 65.82),
        (60,  84.52, 68.73),
        (100, 83.27, 67.41),
    ],
    "table63": [
        ("传统静态分析（Cppcheck）",    71.34, 58.62, 64.37, 28.65),
        ("纯LLM Zero-Shot",            68.91, 72.14, 70.49, 31.09),
        ("单模态RAG文本",               74.28, 75.83, 75.05, 25.72),
        ("本系统三路RRF+Actor-Critic",  88.63, 84.17, 86.34,  9.87),
    ],
    "table64": [
        ("单轮LLM推理",              71.23, 28.77, 34.82),
        ("线性多智能体",             77.56, 22.44, 18.63),
        ("Actor-Critic无GBNF",       83.14, 16.86, 12.47),
        ("Actor-Critic+GBNF（完整）", 86.34,  9.87,  4.93),
    ],
    "table65": [
        ("CWE-121", "栈缓冲区溢出",   81.34, 85.72, 4.38),
        ("CWE-122", "堆缓冲区溢出",   82.17, 86.03, 3.86),
        ("CWE-415", "双重释放",       79.83, 84.61, 4.78),
        ("CWE-416", "释放后使用",     80.56, 83.29, 2.73),
        ("CWE-476", "空指针解引用",   84.92, 86.14, 1.22),
    ],
}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description="生成论文第六章 LaTeX 表格")
    p.add_argument("--input",   default="results/all_tables.json", help="JSON 结果文件路径")
    p.add_argument("--dry-run", action="store_true",               help="使用内置模拟数据")
    p.add_argument("--output",  default="",                        help="输出 .tex 文件路径（默认打印到 stdout）")
    args = p.parse_args()

    if args.dry_run:
        data = DRY_RUN
    else:
        input_path = Path(args.input)
        if not input_path.exists():
            print(f"错误: 找不到 {input_path}，请先运行 run_benchmark.py 或使用 --dry-run", file=sys.stderr)
            sys.exit(1)
        data = json.loads(input_path.read_text(encoding="utf-8"))

    latex = generate_all_latex(data)

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(latex, encoding="utf-8")
        print(f"LaTeX 表格已写入 {out}")
    else:
        print(latex)


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).parent.parent))
    main()
