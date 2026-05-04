# MM-RAG: Multi-Modal Enhanced RAG 代码漏洞智能检测系统

基于大语言模型与检索增强生成技术的 C/C++ 代码漏洞检测系统，专为装备软件安全审计设计。

## 系统特性

- **物理行号保真**：所有检测结果精准映射回原始代码物理行号
- **完全离线运行**：部署于涉密局域网，无任何外部网络依赖
- **白盒化证据链**：输出完整 Source→Sink 路径 + Attacker-Defender 对抗辩论记录
- **Actor-Critic 博弈框架**：通过 Attacker/Defender/Judge 三智能体对抗辩论降低误报

## 环境要求

- Python >= 3.10
- （可选）NVIDIA GPU + CUDA 用于加速推理和嵌入计算
- （可选）C++ 编译工具链（仅安装 `llama-cpp-python` 时需要）

## 快速开始

### 1. 安装基础依赖

```bash
# 克隆项目
cd "graduation project"

# 安装核心包（解析层 + 检索层）
pip install -e ".[dev]"
```

### 2. 验证安装

```bash
# 运行全部测试（114 项，无需 GPU 或模型文件）
pytest tests/ -v
```

### 3. 解析层使用

```bash
# 解析 C 文件，输出函数列表、CFG、代码分块
python -m mmrag.parsing your_code.c --output text

# 执行后向切片（从第 42 行的 buffer 变量向后追溯）
python -m mmrag.parsing your_code.c --slice 42:buffer --direction backward

# JSON 格式输出（供程序消费）
python -m mmrag.parsing your_code.c --output json > result.json
```

### 4. 检索层使用

```bash
# 索引一个 C 文件（仅 BM25，无需嵌入模型）
python -m mmrag.retrieval index your_code.c --bm25-path ./index/bm25.pkl

# 查询相似代码片段
python -m mmrag.retrieval query "malloc free buffer overflow" --mode bm25 --bm25-path ./index/bm25.pkl

# 带元数据过滤的查询
python -m mmrag.retrieval query "strcpy" --filter-func dangerous_function --mode bm25 --bm25-path ./index/bm25.pkl

# 查看索引统计
python -m mmrag.retrieval stats --bm25-path ./index/bm25.pkl
```

### 5. 推理层使用（需要 GGUF 模型）

```bash
# 分析整个文件中的所有含危险 API 的函数
python -m mmrag.reasoning analyze your_code.c \
    --model-path /path/to/qwen2.5-coder-32b.Q4_K_M.gguf \
    --output text

# 仅分析指定函数
python -m mmrag.reasoning analyze your_code.c \
    --model-path /path/to/qwen2.5-coder-32b.Q4_K_M.gguf \
    --function resource_handler \
    --output json

# 结合检索上下文进行分析
python -m mmrag.reasoning analyze your_code.c \
    --model-path /path/to/qwen2.5-coder-32b.Q4_K_M.gguf \
    --bm25-path ./index/bm25.pkl \
    --output text
```

---

## 模型准备

本系统不包含训练过程——使用预训练模型进行推理。需要准备两个模型：

### 推理模型（必需）

系统使用 Qwen2.5-Coder-32B 的 GGUF 量化版本作为推理基座。

**下载方式**（在有网络的机器上执行，然后拷贝到离线环境）：

```bash
# 推荐 Q4_K_M 量化（约 20GB，平衡质量与速度）
# 从 HuggingFace 下载
huggingface-cli download Qwen/Qwen2.5-Coder-32B-Instruct-GGUF \
    qwen2.5-coder-32b-instruct-q4_k_m.gguf \
    --local-dir ./models/

# 或使用更小的量化版本（约 13GB，适合显存较小的 GPU）
huggingface-cli download Qwen/Qwen2.5-Coder-32B-Instruct-GGUF \
    qwen2.5-coder-32b-instruct-q3_k_m.gguf \
    --local-dir ./models/
```

### 嵌入模型（可选，用于稠密检索）

```bash
# 下载 CodeFuse-CGE 嵌入模型
huggingface-cli download codefuse-ai/CodeFuse-CGE-Small \
    --local-dir ./models/codefuse-cge-small/
```

### 模型文件放置

```
models/
├── qwen2.5-coder-32b-instruct-q4_k_m.gguf   # 推理模型
└── codefuse-cge-small/                        # 嵌入模型目录
    ├── config.json
    ├── tokenizer.json
    ├── model.safetensors
    └── ...
```

---

## GPU 加速配置

### 推理层 GPU（llama-cpp-python + CUDA）

`llama-cpp-python` 默认安装为 CPU 版本。要启用 CUDA 加速，**必须**重新编译安装：

```bash
# Linux / WSL
CMAKE_ARGS="-DGGML_CUDA=on" pip install llama-cpp-python --force-reinstall --no-cache-dir

# Windows (需要 Visual Studio Build Tools + CUDA Toolkit)
set CMAKE_ARGS=-DGGML_CUDA=on
pip install llama-cpp-python --force-reinstall --no-cache-dir
```

系统会在运行时自动检测 GPU 支持：
- 调用 `llama_supports_gpu_offload()` 检查编译标志
- 如果请求了 GPU（`n_gpu_layers != 0`）但编译不支持，会输出明确警告并自动回退到 CPU
- 默认 `n_gpu_layers=-1` 表示将所有层卸载到 GPU

### 嵌入层 GPU（PyTorch + CUDA）

嵌入模型通过 `sentence-transformers` 加载，自动检测 CUDA：

```python
# 配置中 device="auto" 时自动选择
# 等价于: "cuda" if torch.cuda.is_available() else "cpu"
```

如果 PyTorch 安装时未包含 CUDA 支持，需要重新安装：

```bash
pip install torch --index-url https://download.pytorch.org/whl/cu121
```

---

## 完整工作流示例

以下演示从源文件到漏洞报告的完整流程：

```bash
# Step 1: 解析并索引目标代码库
python -m mmrag.retrieval index target_project/src/network.c --bm25-path ./index/bm25.pkl
python -m mmrag.retrieval index target_project/src/parser.c --bm25-path ./index/bm25.pkl

# Step 2: 执行漏洞分析（结合检索上下文）
python -m mmrag.reasoning analyze target_project/src/network.c \
    --model-path ./models/qwen2.5-coder-32b-instruct-q4_k_m.gguf \
    --bm25-path ./index/bm25.pkl \
    --n-gpu-layers -1 \
    --output json > reports/network_report.json

# Step 3: 查看文本格式报告
python -m mmrag.reasoning analyze target_project/src/network.c \
    --model-path ./models/qwen2.5-coder-32b-instruct-q4_k_m.gguf \
    --bm25-path ./index/bm25.pkl \
    --output text
```

### 输出示例

```
============================================================
Function: process_request() [45-120]
Verdict:  VULNERABLE (confidence: 0.85)
Type:     CWE-122: Heap-based Buffer Overflow
Source→Sink Path:
  line   52 [source      ] user_len = recv(sock, len_buf, 4, 0);
  line   58 [propagation ] buf = malloc(user_len);
  line   73 [propagation ] bytes_read = recv(sock, buf, user_len, 0);
  line   89 [sink        ] memcpy(output, buf, bytes_read);
Time:     12.3s

--- Round 1 ---
  Attacker: CWE-122: Heap-based Buffer Overflow (conf=0.85)
    user_len comes from network without validation, used as malloc size...
  Defender: partially_mitigated
    malloc return value is checked for NULL at line 60...

--- Round 2 ---
  Attacker: CWE-122: Heap-based Buffer Overflow (conf=0.80)
    NULL check only prevents null deref, not overflow...
  Defender: unmitigated
    Acknowledged: no upper bound check on user_len...

--- Judge ---
  Vulnerable. The user-controlled length from network is used directly...
```

---

## 离线部署指南

在涉密局域网中部署时，需要在有网络的机器上预先准备所有依赖：

```bash
# 1. 在联网机器上下载所有 wheel 包
pip download -e ".[dev,gpu]" -d ./wheels/

# 2. 下载模型文件（见"模型准备"章节）

# 3. 将 wheels/ 目录和 models/ 目录拷贝到离线机器

# 4. 在离线机器上安装
pip install --no-index --find-links=./wheels/ -e ".[dev]"

# 5. 如需 GPU 推理，在离线机器上编译安装 llama-cpp-python
# （需要预先安装 CUDA Toolkit 和 C++ 编译器）
CMAKE_ARGS="-DGGML_CUDA=on" pip install --no-index --find-links=./wheels/ llama-cpp-python
```

### 安全注意事项

系统通过以下机制确保不会发起任何外部网络请求：

| 防护点 | 机制 | 位置 |
|--------|------|------|
| HuggingFace Hub | `HF_HUB_OFFLINE=1` 环境变量 | embedding_index.py |
| Transformers | `TRANSFORMERS_OFFLINE=1` 环境变量 | embedding_index.py |
| SentenceTransformer | `local_files_only=True` 参数 | embedding_index.py |
| 模型加载 | `config.model_path` 必须为本地绝对路径 | llm_backend.py |

---

## 项目架构

```
解析层 (Phase 1)          检索层 (Phase 2)          推理层 (Phase 3)
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────────┐
│ C/C++ 源文件     │      │ Chunk 集合       │      │ 函数 + CFG + 切片    │
│       │         │      │       │         │      │       │             │
│       ▼         │      │       ▼         │      │       ▼             │
│ Tree-sitter AST │      │ BM25 分词+索引   │      │ 危险 API 扫描       │
│       │         │      │       │         │      │       │             │
│       ▼         │      │       ▼         │      │       ▼             │
│ 函数提取        │─────▶│ Embedding 编码   │─────▶│ Attacker 分析       │
│       │         │      │       │         │      │       │             │
│       ▼         │      │       ▼         │      │       ▼             │
│ CFG 构建        │      │ RRF 融合检索     │      │ Defender 反驳       │
│       │         │      │                 │      │       │             │
│       ▼         │      │                 │      │       ▼             │
│ 程序切片        │      │                 │      │ 2轮辩论 → Judge     │
│       │         │      │                 │      │       │             │
│       ▼         │      │                 │      │       ▼             │
│ 代码分块        │      │                 │      │ VulnerabilityReport │
└─────────────────┘      └─────────────────┘      └─────────────────────┘
```

---

## 测试

```bash
# 运行全部 114 项测试
pytest tests/ -v

# 仅运行某一层的测试
pytest tests/test_parser.py tests/test_cfg.py tests/test_slicer.py tests/test_chunker.py -v  # 解析层
pytest tests/test_tokenizer.py tests/test_bm25_index.py tests/test_fusion.py tests/test_retriever.py -v  # 检索层
pytest tests/test_reasoning_models.py tests/test_evidence.py tests/test_prompts.py tests/test_agents.py tests/test_orchestrator.py -v  # 推理层

# 容错性测试（验证系统处理语法错误文件不崩溃）
pytest tests/test_robustness.py -v
```

所有测试均不需要真实的 LLM 模型或 GPU——推理层测试使用 `MockLLMBackend` 模拟 LLM 响应。

---

## 关于训练

本系统**不包含模型训练过程**。它采用"预训练模型 + 推理时约束"的范式：

1. **推理模型**（Qwen2.5-Coder-32B）：直接使用社区发布的预训练+指令微调权重，通过 GBNF 语法在推理时强制输出结构化 JSON，无需额外微调。
2. **嵌入模型**（CodeFuse-CGE）：直接使用预训练的代码嵌入模型，无需训练。
3. **BM25 索引**：纯统计方法，无需训练——对目标代码库执行一次 `index` 命令即可构建。

如果未来需要针对特定代码库进行微调，可以：
- 收集已确认的漏洞样本作为正例
- 使用 LoRA/QLoRA 对 Qwen2.5-Coder-32B 进行轻量微调
- 将微调后的模型导出为 GGUF 格式，替换 `--model-path` 即可

---

## 常见问题

**Q: 系统支持哪些 C/C++ 代码？**
A: 支持 `.c`、`.h`、`.cpp`、`.cc`、`.cxx`、`.hpp`、`.hxx` 文件。由于使用 Tree-sitter 而非 Clang，不需要完整的编译环境，可以分析缺少头文件的单个源文件。

**Q: 分析一个函数需要多长时间？**
A: 取决于模型大小和硬件。使用 Q4_K_M 量化 + RTX 4090 GPU，单个函数的 2 轮辩论（5 次 LLM 调用）约需 10-30 秒。CPU 模式下约需 2-5 分钟。

**Q: 如何降低误报率？**
A: 系统的 Actor-Critic 辩论机制本身就是降低误报的核心设计。此外可以：调高 Judge 的置信度阈值（只报告 confidence > 0.8 的结果）；使用 `--bm25-path` 提供检索上下文让模型参考类似代码模式。

**Q: 遇到 "GPU offload requested but compiled WITHOUT GPU support" 警告怎么办？**
A: 需要重新编译 llama-cpp-python：`CMAKE_ARGS="-DGGML_CUDA=on" pip install llama-cpp-python --force-reinstall --no-cache-dir`。确保系统已安装 CUDA Toolkit。
