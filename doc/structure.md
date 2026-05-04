# MM-RAG：基于多模态增强 RAG 的 C/C++ 漏洞检测系统

## 1. 项目概述

### 1.1 核心目标

MM-RAG 是一个面向 C/C++ 遗留代码的深度漏洞挖掘系统。它将大语言模型（LLM）的推理能力与检索增强生成（RAG）技术相结合，通过 **Actor-Critic 对抗辩论框架** 对代码进行多轮分析，最终输出带有完整证据链的漏洞报告。

系统的设计初衷是解决传统静态分析工具的两个核心痛点：

- **误报率高**：传统工具缺乏语义理解能力，对上下文不敏感。MM-RAG 通过 Attacker-Defender-Judge 三方辩论机制，让 LLM 从攻防两个视角审视代码，显著降低误报。
- **证据不透明**：传统工具通常只给出"有漏洞/无漏洞"的结论。MM-RAG 输出完整的 Source→Sink 数据流路径、辩论记录和置信度评分，审计人员可以逐行审查 LLM 的推理过程。

### 1.2 三大设计约束

整个系统的架构决策围绕三个硬约束展开：

**约束一：物理行号保真**

所有检测结果必须精确映射到原始源码的物理行号。系统不做宏展开、不做 `#include` 内联、不做任何破坏代码结构的预处理。从 AST 节点到 Source-Sink 路径中的每一个点，都携带 1-indexed 的行列号信息。这意味着审计人员拿到报告后，可以直接在原始源文件中定位问题代码。

**约束二：完全离线运行**

系统设计用于部署在涉密网络的物理隔离环境中，不允许任何外部网络访问。具体措施包括：

- 推理模型使用 GGUF 格式本地量化文件（Qwen2.5-Coder-32B）
- Embedding 模型使用本地目录（CodeFuse-CGE-Small）
- 强制设置 `HF_HUB_OFFLINE=1`、`TRANSFORMERS_OFFLINE=1` 环境变量
- 模型加载时 `trust_remote_code=False`、`local_files_only=True`

**约束三：白盒证据链**

系统不是黑盒——每个漏洞判定都附带完整的推理过程：

- Attacker 的攻击论证（漏洞类型、置信度、Source/Sink 定位、数据流路径）
- Defender 的防御论证（缓解措施、误报指标）
- 两轮辩论的完整记录
- Judge 的最终裁决（综合证据、关键发现）
- 经 CFG 可达性验证的 Source→Sink 物理路径

### 1.3 技术选型总览

| 组件 | 技术选型 | 选型理由 |
|------|---------|---------|
| AST 解析 | Tree-sitter | 无需编译环境，增量解析，容错性强 |
| 稀疏检索 | BM25Okapi (rank-bm25) | 关键词精确匹配，对 API 名称敏感 |
| 稠密检索 | sentence-transformers + CodeFuse-CGE-Small | 代码语义理解，离线可用 |
| 检索融合 | Reciprocal Rank Fusion (RRF) | 无需训练，权重可调，鲁棒性好 |
| 推理模型 | Qwen2.5-Coder-32B (GGUF) | 代码理解能力强，支持本地量化推理 |
| 推理引擎 | llama-cpp-python | GGUF 原生支持，GPU/CPU 自适应 |
| 结构化输出 | GBNF 文法约束解码 | 强制 LLM 输出合法 JSON，无需后处理 |
| 数据模型 | Pydantic v2 | 类型安全，序列化/反序列化一致 |
| 微调训练 | sentence-transformers + MNRL | 对比学习标准方案，in-batch negatives |

## 2. 系统架构总览

### 2.1 三层流水线架构图

```
┌─────────────────────────────────────────────────────────────────────┐
│                        C/C++ 源文件输入                              │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    第一层：解析层 (Parsing)                           │
│                                                                     │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────────┐    │
│  │ AST 解析  │──▶│ CFG 构建  │──▶│ 程序切片  │   │  RAG 分块    │    │
│  │ (Tree-   │   │          │   │ (前向/   │   │ (函数/块/   │    │
│  │  sitter) │   │          │   │  后向)   │   │  切片粒度)  │    │
│  └──────────┘   └──────────┘   └──────────┘   └──────────────┘    │
│                                                                     │
│  输出: FunctionInfo, CFG, Slice, Chunk                              │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    第二层：检索层 (Retrieval)                         │
│                                                                     │
│  ┌──────────────┐   ┌────────────────┐   ┌───────────────────┐    │
│  │ BM25 稀疏检索 │   │ Embedding 稠密  │   │  RRF 倒数排名融合  │    │
│  │ (关键词匹配)  │──▶│ 检索 (语义相似) │──▶│  (加权分数合并)   │    │
│  └──────────────┘   └────────────────┘   └───────────────────┘    │
│                                                                     │
│  输出: list[RetrievalResult] — 排序后的相关代码片段                    │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    第三层：推理层 (Reasoning)                         │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │              Actor-Critic 对抗辩论框架                        │   │
│  │                                                             │   │
│  │  第 1 轮:  Attacker 分析 ──▶ Defender 反驳                   │   │
│  │  第 2 轮:  Attacker 再反驳 ──▶ Defender 再反驳               │   │
│  │  裁决:     Judge 综合两轮辩论 ──▶ 最终判定                    │   │
│  │                                                             │   │
│  │  每次 LLM 调用均使用 GBNF 文法约束，强制输出结构化 JSON        │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  输出: VulnerabilityReport (判定 + 置信度 + 证据链 + 辩论记录)       │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 数据流概览

一次完整的漏洞分析流程如下：

```
源文件 (.c/.cpp)
  │
  ├─ parse_file() ──▶ AST Root + list[FunctionInfo]
  │
  ├─ build_cfg(func) ──▶ CFG (基本块 + 边 + 边类型)
  │
  ├─ chunk_file(functions, source) ──▶ list[Chunk] (函数级 + 块级分块)
  │
  ├─ find_dangerous_calls(func) ──▶ [(行号, API名)] (malloc, strcpy, system...)
  │
  ├─ compute_slice(cfg, source, criterion, BACKWARD) ──▶ Slice (数据流切片)
  │
  ├─ retriever.query(query) ──▶ list[RetrievalResult] (BM25 + Embedding + RRF)
  │
  ├─ Attacker.analyze(code, context, cfg_summary, slice_info) ──▶ AttackArgument
  ├─ Defender.defend(code, context, attack_json) ──▶ DefenseArgument
  ├─ Attacker.rebut(code, defense_json, attack_json) ──▶ AttackArgument
  ├─ Defender.rebut(code, attack_json, defense_json) ──▶ DefenseArgument
  ├─ Judge.judge(code, debate_record) ──▶ JudgeVerdict
  │
  ├─ validate_source_sink_path(path, source_lines, cfg) ──▶ 验证后的物理路径
  │
  └─▶ VulnerabilityReport
```

每个函数的分析需要 **5 次 LLM 调用**（2 轮辩论 × 2 方 + 1 次裁决）。系统仅对包含危险 API 调用的函数触发分析，跳过无风险函数以节省推理开销。

### 2.3 模块依赖关系

```
mmrag/
├── parsing/          ← 无外部模块依赖（纯 Tree-sitter + Pydantic）
├── retrieval/        ← 依赖 parsing.models.Chunk
├── reasoning/        ← 依赖 parsing（AST/CFG/Slice）+ retrieval（Retriever）
├── benchmark/        ← 依赖 parsing + retrieval + reasoning（评估全流水线）
└── finetune/         ← 依赖 parsing（分块）+ benchmark（数据集）
```

依赖方向严格单向：`parsing → retrieval → reasoning`。`benchmark` 和 `finetune` 是上层模块，依赖核心三层但不被核心三层依赖。

## 3. 第一层：解析层（mmrag/parsing/）

解析层的职责是将原始 C/C++ 源码转化为结构化的中间表示，为后续检索和推理提供精确的代码语义信息。所有输出均保留物理行号映射。

### 3.1 Tree-sitter AST 解析（ast_parser.py）

**核心设计**：使用 Tree-sitter 进行 AST 解析，而非传统编译器前端（如 Clang）。这一选择基于以下考量：

- **无需编译环境**：Tree-sitter 是纯解析器，不需要头文件、链接库或完整的编译工具链。对于遗留代码（可能缺少依赖）尤为重要。
- **容错解析**：即使源码存在语法错误，Tree-sitter 仍能产出部分 AST（错误节点标记为 `ERROR`），系统不会因单个文件的语法问题而崩溃。
- **增量解析**：Tree-sitter 支持增量更新，适合未来扩展为 IDE 集成场景。

**关键函数**：

- `parse_file(path, language=None)` → `(ASTNode, list[FunctionInfo], bytes)` — 解析文件，自动检测语言（C/C++），返回 AST 根节点、函数列表和原始字节
- `parse_source(source_bytes, language)` → `(ASTNode, list[FunctionInfo])` — 解析内存中的源码
- `collect_errors(root)` → `list[str]` — 收集 AST 中的 ERROR/MISSING 节点

**函数提取逻辑**：遍历 AST 顶层节点，识别 `function_definition` 类型节点，提取函数名、返回类型、参数列表、签名文本、函数体范围和完整子 AST。支持的文件扩展名：`.c`, `.h`, `.cpp`, `.cc`, `.cxx`, `.hpp`, `.hxx`。

### 3.2 控制流图构建（cfg_builder.py）

**核心设计**：从函数 AST 构建控制流图（CFG），用于程序切片和证据链验证。

**CFG 结构**：
- **BasicBlock**：包含一组顺序执行的语句（AST 节点），有唯一 ID、前驱/后继列表
- **CFGEdge**：连接两个基本块，携带边类型信息
- **入口/出口块**：每个 CFG 有唯一的 entry 和 exit 块

**支持的控制流结构**：

| 结构 | 边类型 |
|------|--------|
| if/else | `true_branch`, `false_branch` |
| for/while/do-while | `true_branch`, `false_branch`, `back_edge` |
| switch/case | `case`, `default` |
| break | `break` |
| continue | `continue` |
| goto | `goto` |
| return | `return` |
| 顺序执行 | `unconditional` |

**构建算法**：递归遍历函数体 AST，遇到复合语句（if/for/while/switch）时创建新的基本块和对应的分支边。对于 goto 语句，记录标签位置并在后处理阶段连接跳转边。

### 3.3 程序切片（slicer.py）— DEF/USE 分析与前向/后向切片

**核心设计**：基于 CFG 的过程内程序切片，用于提取与特定变量/行相关的代码子集。这是为推理层提供精确上下文的关键技术。

**DEF/USE 分析**（`_extract_def_use` 函数）：

对每条语句计算定义集（DEF）和使用集（USE）：

- **赋值语句** `a = expr`：DEF = {a}，USE = expr 中的所有变量
- **声明初始化** `int x = expr`：DEF = {x}，USE = expr 中的变量
- **自增/复合赋值** `x++`, `x += y`：DEF = {x}，USE = {x, y}
- **函数调用** `f(a, b)`：USE = {a, b}（参数），不分析被调用函数名
- **指针/结构体/数组**：使用归一化访问路径（如 `ptr->arr[].x`），索引变量加入 USE 集

**归一化访问路径**（`_normalize_access_path`）：

将复杂的左值表达式归一化为统一格式，使得 `ptr->arr[i].x` 和 `ptr->arr[j].x` 被识别为同一变量的不同访问：
- `ptr->field` → `"ptr->field"`
- `arr[i]` → `"arr[]"`（索引变量 `i` 加入 USE 集）
- `*ptr` → `"*ptr"`

**后向切片**（Backward Slice）：

从切片准则（行号 + 可选变量）出发，沿 CFG 反向追踪所有影响该点的语句：

1. 确定种子语句的 USE 集作为初始追踪变量
2. 沿基本块内向上搜索，找到定义该变量的语句
3. 将该语句的 USE 集加入工作列表
4. 跨基本块时，沿前驱边传播
5. 重复直到工作列表为空

**前向切片**（Forward Slice）：

从切片准则出发，沿 CFG 正向追踪所有受该点影响的语句。逻辑对称：追踪 DEF 集中的变量在后续语句中的 USE。

**在漏洞检测中的应用**：对每个危险 API 调用（如 `malloc`），计算后向切片，得到所有影响该调用参数的代码行。这些信息作为上下文注入 Attacker 的 prompt，帮助 LLM 理解数据流。

### 3.4 RAG 分块策略（chunker.py）

**核心设计**：将函数代码切分为适合检索的 Chunk，平衡粒度与上下文完整性。

**分块策略**：

1. **函数级分块**（ChunkKind.FUNCTION）：每个函数整体作为一个 Chunk。这是默认粒度，保证上下文完整。
2. **块级分块**（ChunkKind.BLOCK）：对于超过 `split_threshold`（默认 30 行）的长函数，进一步按控制流结构拆分：
   - 复合语句（if/for/while/do/switch）各自成为独立 Chunk
   - 连续的简单语句按 `max_simple_group`（默认 15 行）分组

**Chunk 元数据**：每个 Chunk 携带丰富的元数据用于检索过滤：
- `chunk_id`：`"file_path:func_name:start_line-end_line"` 格式的唯一标识
- `kind`：function / block / slice
- `file_path`、`function_name`：来源信息
- `source_range`：精确的行列号范围
- `ast_node_types`：该 Chunk 包含的 AST 节点类型集合（用于结构相似性匹配）
- `metadata`：扩展字段（如 `has_errors`、`context` 签名）

### 3.5 数据模型（models.py）

解析层定义了系统的核心数据结构，所有后续层都依赖这些模型：

```
SourceLocation (line, column)           ← 1-indexed 物理位置
    └── SourceRange (start, end, byte offsets)
            └── ASTNode (type, text, children, source_range)
                    └── FunctionInfo (name, params, body_range, ast)
                            └── CFG (blocks, edges, entry/exit)
                            └── Chunk (id, kind, text, metadata)
                            └── Slice (direction, criterion, included_lines)
```

所有模型均为 Pydantic BaseModel，支持 JSON 序列化/反序列化，确保数据在层间传递时类型安全。

## 4. 第二层：检索层（mmrag/retrieval/）

检索层的职责是从已索引的代码库中，为当前待分析的函数找到语义相关的代码片段作为上下文。它采用经典的"稀疏 + 稠密"双路检索架构，通过 RRF 融合两路结果。

### 4.1 代码感知分词器（tokenizer.py）

BM25 的检索质量高度依赖分词质量。通用英文分词器无法正确处理代码中的标识符、运算符和注释，因此系统实现了专用的 C/C++ 代码分词器。

**分词流水线**（4 步）：

1. **去除注释和字符串字面量**（`_strip_comments_and_strings`）：用正则移除 `//` 行注释、`/* */` 块注释、`"..."` 字符串和 `'...'` 字符字面量，替换为空格以保留位置信息。
2. **保护多字符运算符**（`_protect_operators`）：将 `->`, `<<`, `>=`, `&&` 等 22 种多字符运算符替换为占位符（如 `_OP_ARROW_`），防止后续分割时被拆散。
3. **按非字母数字字符分割**：得到原始 token 列表。
4. **标识符展开**（`_split_identifier`）：对每个 token 进行 camelCase 和 snake_case 拆分。例如 `myBufferSize` → `["mybuffersize", "my", "buffer", "size"]`。保留原始复合词和拆分后的子词，提高召回率。

**查询分词**（`tokenize_query`）：与代码分词相同的流水线，但跳过注释/字符串去除步骤（查询文本中不包含这些结构）。

**关键词保留**：维护 75 个 C/C++ 关键词列表（含标准库函数名如 `malloc`, `strcpy`），单字符 token 默认过滤，但关键词（如 `if`, `do`）保留。

### 4.2 BM25 稀疏检索（bm25_index.py）

**实现**：基于 `rank-bm25` 库的 BM25Okapi 算法。

**索引构建**：
- 输入：`list[Chunk]`
- 对每个 Chunk 的 `text` 字段调用 `tokenize_code()` 得到 token 列表
- 构建 BM25Okapi 倒排索引
- 同时维护 `chunk_id → Chunk` 的映射表

**查询流程**：
- 对查询文本调用 `tokenize_query()` 分词
- BM25 计算每个文档的相关性分数
- 支持 `MetadataFilter` 过滤（按文件路径、函数名、AST 节点类型、Chunk 类型）
- 返回 top-k 结果，附带分数和排名

**优势**：BM25 对精确的 API 名称匹配非常敏感。当查询包含 `malloc` 或 `strcpy` 时，BM25 能精准找到包含这些调用的代码片段，这是稠密检索容易模糊化的场景。

### 4.3 稠密向量检索（embedding_index.py）— 离线约束实现

**实现**：基于 `sentence-transformers` 的 SentenceTransformer 模型，默认使用 CodeFuse-CGE-Small。

**离线约束的实现细节**：

```python
os.environ["HF_HUB_OFFLINE"] = "1"
os.environ["TRANSFORMERS_OFFLINE"] = "1"

model = SentenceTransformer(
    config.model_path,          # 必须是本地绝对路径
    device=device,
    trust_remote_code=False,    # 禁止执行远程代码
    local_files_only=True,      # 仅加载本地文件
)
```

如果 `model_path` 为空，直接抛出 `ValueError`，不会尝试从 HuggingFace Hub 下载。

**索引构建**：
- 按 `embedding_batch_size`（默认 64）分批编码
- 使用 L2 归一化（`normalize_embeddings=True`），使余弦相似度退化为内积
- 所有向量堆叠为 `np.ndarray`

**查询流程**：
- 编码查询文本为归一化向量
- 计算 `scores = embeddings @ query_vec`（内积 = 余弦相似度）
- 应用元数据过滤掩码（乘以 0/1 mask）
- 返回 top-k 结果（过滤掉 score ≤ 0 的结果）

**设备自适应**：`device="auto"` 时自动检测 CUDA 可用性，有 GPU 用 GPU，否则回退 CPU。

**持久化**：使用 pickle 序列化 chunk_ids、chunk 元数据和 embedding 矩阵。加载时重建 Chunk 对象。

### 4.4 倒数排名融合 RRF（fusion.py）

**算法**：Reciprocal Rank Fusion 是一种无需训练的排名融合方法，通过排名位置而非原始分数来合并多路检索结果。

**公式**：

```
RRF_score(doc) = Σ weight_i / (k + rank_i(doc))
```

其中 `k` 是平滑常数（默认 60），`rank_i(doc)` 是文档在第 i 路检索中的排名，`weight_i` 是该路的权重。

**实现**：

```python
for r in bm25_results:
    scores[r.chunk_id] += bm25_weight / (rrf_k + r.rank)
for r in embedding_results:
    scores[r.chunk_id] += embedding_weight / (rrf_k + r.rank)
```

**设计选择**：
- 使用 RRF 而非学习型融合（如 LambdaMART），因为 RRF 无需训练数据，在小数据场景下鲁棒性更好
- `bm25_weight` 和 `embedding_weight` 均默认为 1.0，可通过配置调整
- 两路各取 `top_k × multiplier`（默认 3 倍）候选，确保融合后有足够的候选池

### 4.5 统一检索器接口（retriever.py）

`Retriever` 类封装了 BM25 和 Embedding 两个索引，提供统一的查询接口：

**索引构建**（`index(chunks)`）：
- 始终构建 BM25 索引
- 仅当 `config.model_path` 非空时构建 Embedding 索引
- 返回 `IndexStats`（chunk 数量、索引状态、模型信息）

**查询模式**：
- `query()` — 混合查询：两路检索 + RRF 融合
- `query_bm25_only()` — 仅 BM25
- `query_embedding_only()` — 仅 Embedding

**优雅降级**：如果没有配置 Embedding 模型，`query()` 自动退化为纯 BM25 检索，不会报错。这使得系统在没有 GPU 或没有 Embedding 模型的环境中仍然可用。

**持久化**：`save()` 分别保存 BM25 索引、Embedding 索引和 Chunk 注册表（3 个 pickle 文件）。`load()` 按需加载存在的索引文件。

## 5. 第三层：推理层（mmrag/reasoning/）

推理层是系统的核心决策引擎。它将解析层提供的结构化代码信息和检索层提供的相似代码上下文，注入到一个三智能体对抗辩论框架中，由 LLM 进行多轮推理，最终输出带有完整证据链的漏洞判定。

### 5.1 LLM 后端与 GGUF 推理（llm_backend.py）

**核心设计**：通过 `llama-cpp-python` 加载 GGUF 格式的量化模型，在本地完成推理。

**LLMConfig 配置**：

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `model_path` | `""` | GGUF 文件本地路径（必填） |
| `n_gpu_layers` | `-1` | GPU 层数，-1 表示全部卸载到 GPU |
| `n_ctx` | `16384` | 上下文窗口长度 |
| `n_threads` | `4` | CPU 线程数 |
| `temperature` | `0.1` | 低温度保证输出一致性 |
| `max_tokens` | `2048` | 最大输出 token 数 |
| `seed` | `42` | 随机种子，保证可复现 |
| `device` | `"auto"` | 自动检测 GPU |

**LLMBackend 接口**：

- `generate(prompt, max_tokens, temperature)` → `str` — 自由文本生成
- `generate_structured(prompt, grammar_str, max_tokens, temperature)` → `str` — GBNF 约束生成

**MockLLMBackend**：用于测试的模拟后端，通过关键词路由返回预设 JSON 响应。所有 114+ 个测试均使用 Mock 后端，无需真实模型或 GPU。其设计要点：

- 继承 `LLMBackend`，保持接口一致
- `set_response(keyword, response)` — 按 prompt 中的关键词匹配返回对应响应
- `_call_log` — 记录所有调用，用于验证调用次数和参数
- `_default_response` — 无匹配时的兜底响应（默认 `"{}"`）

### 5.2 GBNF 约束解码文法（grammars.py）

**核心问题**：LLM 的自由文本输出不可靠——可能输出非法 JSON、遗漏必要字段、或添加多余内容。GBNF（GGML BNF）文法在 token 采样阶段强制约束输出格式，从根本上消除格式错误。

**三套文法**：

**ATTACKER_GRAMMAR** — 约束 Attacker 输出：
```json
{
  "vulnerability_type": "string",
  "confidence": 0.0-1.0,
  "source": {"line": int, "code": "string", "description": "string", "role": "source"},
  "sink": {"line": int, "code": "string", "description": "string", "role": "sink"},
  "data_flow_path": [{"line": int, "code": "string", "description": "string", "role": "string"}, ...],
  "reasoning": "string"
}
```

**DEFENDER_GRAMMAR** — 约束 Defender 输出：
```json
{
  "verdict": "safe|partially_mitigated|unmitigated",
  "mitigations": [{"line": int, "code": "string", "description": "string"}, ...],
  "false_positive_indicators": ["string", ...],
  "reasoning": "string"
}
```

**JUDGE_GRAMMAR** — 约束 Judge 输出：
```json
{
  "verdict": "VULNERABLE|SAFE|UNCERTAIN",
  "confidence": 0.0-1.0,
  "vulnerability_type": "string",
  "source_sink_path": [{"line": int, "code": "string", "description": "string", "role": "string"}, ...],
  "key_evidence": {"string": "string", ...},
  "summary": "string"
}
```

**共享基元**：三套文法共用 `ws`（空白）、`string`（JSON 字符串）、`int`（整数）、`float`（浮点数）等基础规则，减少重复定义。

### 5.3 Prompt 工程（prompts.py）

系统定义了 5 个 prompt 构建函数，对应辩论的 5 个阶段。所有 prompt 遵循统一的结构设计：

**通用结构**：
1. **角色设定**：明确智能体身份（安全审计员 / 软件工程师 / 公正裁判）
2. **带行号的代码展示**：源码按 `行号 | 代码` 格式呈现，确保 LLM 输出的行号与物理行号一致
3. **结构化上下文注入**：CFG 摘要、数据流切片、检索到的相似代码片段
4. **输出格式要求**：明确要求 JSON 格式（配合 GBNF 文法双重保障）

**5 个 prompt 函数**：

| 函数 | 阶段 | 角色 | 输入上下文 |
|------|------|------|-----------|
| `build_attacker_prompt` | 第 1 轮攻击 | 安全审计员 | 代码 + 检索上下文 + CFG 摘要 + 切片信息 |
| `build_defender_prompt` | 第 1 轮防御 | 软件工程师 | 代码 + 检索上下文 + Attacker 的论证 |
| `build_attacker_rebuttal_prompt` | 第 2 轮攻击 | 安全审计员 | 代码 + Defender 的论证 + 原始攻击论证 |
| `build_defender_rebuttal_prompt` | 第 2 轮防御 | 软件工程师 | 代码 + Attacker 的反驳 + 原始防御论证 |
| `build_judge_prompt` | 裁决 | 公正裁判 | 代码 + 完整辩论记录 |

**行号展示格式**：
```
  1 | void resource_handler(int flag) {
  2 |     char *buf = (char *)malloc(256);
  3 |     if (buf == NULL) return;
  ...
```

这种格式使 LLM 在输出 `source`/`sink` 的 `line` 字段时，能直接引用物理行号。

### 5.4 三智能体辩论框架（agents.py）— Attacker / Defender / Judge

**核心设计**：借鉴对抗性辩论（Adversarial Debate）的思想，让两个持不同立场的智能体围绕代码安全性展开辩论，第三方裁判综合双方论点做出最终判定。

**AttackerAgent（安全审计员）**：

- `analyze(code, context_chunks, cfg_summary, slice_info)` → `AttackArgument` — 第 1 轮：分析代码，尝试找出漏洞
- `rebut(code, defender_argument, original_attack)` → `AttackArgument` — 第 2 轮：针对 Defender 的反驳进行再反驳

输出结构：漏洞类型、置信度（0-1）、Source 点、Sink 点、完整数据流路径、推理过程。

**DefenderAgent（软件工程师）**：

- `defend(code, context_chunks, attacker_argument)` → `DefenseArgument` — 第 1 轮：审查 Attacker 的论证，指出缓解措施
- `rebut(code, attacker_rebuttal, original_defense)` → `DefenseArgument` — 第 2 轮：针对 Attacker 的再反驳进行回应

输出结构：判定（safe / partially_mitigated / unmitigated）、缓解措施列表、误报指标、推理过程。

**JudgeAgent（公正裁判）**：

- `judge(code, debate_record)` → `JudgeVerdict` — 综合两轮辩论记录，做出最终裁决

输出结构：判定（VULNERABLE / SAFE / UNCERTAIN）、置信度、漏洞类型、Source→Sink 路径、关键证据、总结。

**重试机制**：每个智能体的 LLM 调用都有两级重试：
1. 第一次尝试：`temperature=0.1`（低温度，确定性强）
2. 若失败，第二次尝试：`temperature=0.3`（稍高温度，增加多样性）
3. 若仍失败，返回带有错误说明的默认对象（不会抛异常）

**JSON 解析容错**（`_parse_json_safe`）：LLM 输出可能包含前导文本（如 "Here is my analysis:"），解析器会自动定位第一个 `{` 开始解析。

### 5.5 证据链构建与验证（evidence.py）

**危险 API 检测**（`find_dangerous_calls`）：

遍历函数 AST，识别对 30 个危险 API 的调用：

| 类别 | API |
|------|-----|
| 内存管理 | `malloc`, `calloc`, `realloc`, `free` |
| 内存操作 | `memcpy`, `memset`, `memmove`, `memcmp` |
| 字符串操作 | `strcpy`, `strncpy`, `strcat`, `strncat`, `strcmp`, `strncmp`, `strlen` |
| 格式化 I/O | `sprintf`, `snprintf`, `printf`, `fprintf`, `scanf`, `fscanf`, `sscanf` |
| 非格式化 I/O | `gets`, `fgets`, `puts`, `fputs` |
| 文件操作 | `fopen`, `fclose`, `fread`, `fwrite` |
| 命令执行 | `system`, `exec`, `popen`, `execve`, `execvp` |

检测方式：AST 遍历找 `call_expression` 节点，提取 `function` 字段的 `identifier` 子节点，与危险 API 集合匹配。返回 `[(行号, API名)]` 列表。

**CFG 摘要生成**（`build_cfg_summary`）：

将 CFG 压缩为一行文本摘要，注入 prompt 帮助 LLM 理解函数的控制流复杂度：

```
Blocks: 12, Edges: 15; Edge types: unconditional=5, true_branch=4, false_branch=3, back_edge=2, return=1; Contains loops; Contains goto
```

**Source→Sink 路径验证**（`validate_source_sink_path`）：

LLM 输出的 Source→Sink 路径可能包含幻觉（不存在的行号、不可达的代码路径）。验证流程：

1. **行号范围检查**：移除超出源文件行数范围的点
2. **代码文本填充**：如果 LLM 未输出某个点的代码文本，从源文件中自动补全
3. **CFG 可达性验证**：从 CFG 入口块做 BFS 遍历，收集所有可达行号，过滤掉不可达的路径点

这一步是"白盒证据链"约束的关键保障——确保报告中的每个路径点都对应真实可达的代码。

### 5.6 流水线编排器（orchestrator.py）

`VulnerabilityAnalyzer` 是整个系统的顶层编排器，串联三层流水线。

**`analyze_file(file_path)` 流程**：

1. 解析源文件 → AST + 函数列表
2. 为每个函数构建 CFG
3. 生成 Chunk 用于检索
4. **过滤**：仅对包含危险 API 调用的函数触发分析（跳过无风险函数）
5. 对每个目标函数调用 `analyze_function()`

**`analyze_function(func, cfg, source)` 流程**：

1. **证据收集**：
   - 提取函数源码
   - 生成 CFG 摘要
   - 检测危险 API 调用
   - 对每个危险调用计算后向切片
   - 检索相似代码模式（如果 Retriever 可用）

2. **两轮辩论**（5 次 LLM 调用）：
   - Round 1: Attacker 分析 → Defender 反驳
   - Round 2: Attacker 再反驳 → Defender 再反驳
   - Judge 裁决

3. **证据验证**：对 Judge 输出的 Source→Sink 路径进行 CFG 可达性验证

4. **输出**：`VulnerabilityReport`，包含函数名、文件路径、行范围、判定、置信度、漏洞类型、验证后的路径、完整辩论记录、检索上下文 ID、分析耗时

**性能特征**：
- 单函数分析：10-30 秒（GPU + Q4_K_M 量化）或 2-5 分钟（纯 CPU）
- 每个函数 5 次 LLM 调用，是主要的时间开销
- 无危险 API 的函数被跳过，大幅减少不必要的推理

## 6. 评估基准框架（mmrag/benchmark/）

评估基准框架为系统提供量化评估能力，是后续 Embedding 微调和模型迭代的基础设施。它支持检索质量评估和端到端漏洞检测评估两个维度。

### 6.1 数据模型与标注格式

**BenchmarkSample** — 单个测试用例：

| 字段 | 类型 | 说明 |
|------|------|------|
| `sample_id` | `str` | 唯一标识 |
| `file_path` | `str` | 外部文件路径（与 source_code 二选一） |
| `source_code` | `str` | 内联源码（自包含数据集使用） |
| `language` | `str` | `"c"` 或 `"cpp"` |
| `label` | `VulnLabel` | `VULNERABLE` 或 `SAFE` |
| `cwe_id` | `str \| None` | CWE 编号，如 `"CWE-122"` |
| `cwe_name` | `str \| None` | CWE 名称，如 `"Heap-based Buffer Overflow"` |
| `function_name` | `str \| None` | 目标函数名（可选，用于定向分析） |
| `affected_lines` | `list[AffectedLine]` | 漏洞影响的行号列表（用于行级 IoU 评估） |
| `description` | `str` | 漏洞的自然语言描述 |
| `tags` | `list[str]` | 标签（如 `["juliet"]`, `["memory"]`） |

**设计决策**：`source_code` 和 `file_path` 二选一的设计使得数据集可以是自包含的 JSONL 文件（内联源码），也可以引用外部文件（Juliet Test Suite 场景）。

**DetectionResult** — 单个样本的检测结果：

记录预测标签、真实标签、预测 CWE、置信度、是否正确、以及预测行与真实行的 IoU 重叠度。

**DetectionMetrics** — 聚合检测指标：

包含 Accuracy、Precision、Recall、F1、混淆矩阵（TP/FP/TN/FN）、以及按 CWE 分类的 per-CWE 指标分解。

### 6.2 数据集加载（JSONL + Juliet Test Suite）

**JSONL 格式**（主格式）：

每行一个 JSON 对象，对应一个 `BenchmarkSample`。示例：

```json
{"sample_id": "vuln-001", "label": "vulnerable", "cwe_id": "CWE-122", "function_name": "heap_overflow", "source_code": "void heap_overflow(int n) { ... }", "affected_lines": [{"line": 4, "description": "out-of-bounds write"}]}
```

**Juliet Test Suite 目录加载器**（`load_juliet_dir`）：

自动扫描 Juliet 目录结构，按命名规则分类：

- 目录名中提取 CWE 编号：`CWE122_Heap_Based_Buffer_Overflow/` → `CWE-122`
- 文件名包含 `_bad` → `VULNERABLE`
- 文件名包含 `_good` → `SAFE`
- 自动读取源码到 `source_code` 字段
- 支持 `cwe_filter` 参数筛选特定 CWE 类型

**自动格式检测**（`load_dataset`）：

- 路径以 `.jsonl` / `.json` 结尾 → JSONL 格式
- 路径是目录 → Juliet 格式
- 也可通过 `format` 参数显式指定

**格式转换**：`save_jsonl()` 可将 Juliet 加载的样本导出为 JSONL，方便后续复用。

### 6.3 检索质量指标（Recall@K, Precision@K, MRR, NDCG）

所有检索指标均为纯函数实现，输入是检索结果 ID 列表和相关文档 ID 列表：

**Recall@K**：top-K 检索结果中包含的相关文档占全部相关文档的比例。衡量"找全了多少"。

```
Recall@K = |retrieved[:K] ∩ relevant| / |relevant|
```

**Precision@K**：top-K 检索结果中相关文档的比例。衡量"找准了多少"。

```
Precision@K = |retrieved[:K] ∩ relevant| / K
```

**MRR（Mean Reciprocal Rank）**：第一个相关文档的排名倒数的均值。衡量"多快找到第一个相关结果"。

```
MRR = mean(1 / rank_of_first_relevant)
```

**NDCG@K（Normalized Discounted Cumulative Gain）**：考虑排名位置的加权指标，排名越靠前的相关文档贡献越大。

```
DCG@K = Σ rel_i / log2(i + 1)
NDCG@K = DCG@K / IDCG@K
```

**聚合计算**（`compute_retrieval_metrics`）：接收一组 `RetrievalGoldItem`（查询 + 相关文档 ID）和检索结果，对所有查询计算上述指标的均值。

### 6.4 端到端检测指标（Accuracy, P/R/F1, per-CWE 分解）

**混淆矩阵**：

| | 预测 VULNERABLE | 预测 SAFE |
|---|---|---|
| 真实 VULNERABLE | TP | FN |
| 真实 SAFE | FP | TN |

**全局指标**：

- `Accuracy = (TP + TN) / (TP + FP + TN + FN)`
- `Precision = TP / (TP + FP)` — 预测为漏洞的样本中，真正有漏洞的比例
- `Recall = TP / (TP + FN)` — 真正有漏洞的样本中，被检测出来的比例
- `F1 = 2 × Precision × Recall / (Precision + Recall)`

**Per-CWE 分解**：按 CWE 类型分组，分别计算每个 CWE 的 Precision、Recall、F1。这有助于发现系统对哪些漏洞类型检测效果好、哪些需要改进。

**行级 IoU**（`line_overlap_iou`）：预测的漏洞行号集合与真实标注行号集合的交并比。衡量定位精度。

```
IoU = |predicted_lines ∩ ground_truth_lines| / |predicted_lines ∪ ground_truth_lines|
```

### 6.5 评估编排器（BenchmarkEvaluator）

`BenchmarkEvaluator` 将数据集加载、流水线执行和指标计算串联起来：

**初始化**：接收 `dataset`（样本列表）、可选的 `retriever` 和 `analyzer`。

**三种评估模式**：

1. **纯检索评估**（`evaluate_retrieval`）：只需 Retriever，不需要 LLM。适合快速迭代 Embedding 模型。
2. **端到端检测评估**（`evaluate_detection`）：需要完整的 VulnerabilityAnalyzer。对每个样本执行完整流水线，将 `Verdict.VULNERABLE` 映射为 `VulnLabel.VULNERABLE`，计算检测指标。
3. **全量评估**（`evaluate_all`）：同时执行检索和检测评估，输出 `BenchmarkReport`。

**单样本处理流程**（`_run_single_sample`）：

1. 获取源码（从 `source_code` 字段或读取 `file_path`）
2. 调用 `parse_source()` 解析
3. 定位目标函数（如果指定了 `function_name`）
4. 对每个目标函数构建 CFG 并调用 `analyzer.analyze_function()`
5. 收集预测结果，计算行级 IoU
6. 返回 `DetectionResult`

**优雅降级**：`analyzer` 为 None 时跳过检测评估，`retriever` 为 None 时跳过检索评估。不会报错。

## 7. Embedding 微调模块（mmrag/finetune/）

微调模块的目标是通过对比学习（Contrastive Learning）微调 Embedding 模型，使其在漏洞代码检索场景下的表现优于通用代码 Embedding。

### 7.1 三元组生成策略（描述→代码、API 模式、代码→代码）

微调使用三元组 `(anchor, positive, negative)` 作为训练数据。系统实现了三层三元组生成策略：

**第一层：描述→代码三元组**

- **Anchor**：漏洞的自然语言描述 + CWE 信息。例如：`"CWE-122: Heap-based buffer overflow due to writing beyond allocated buffer boundaries. Heap buffer overflow via unchecked malloc followed by out-of-bounds write"`
- **Positive**：包含该漏洞的代码 Chunk
- **Negative**：安全代码的 Chunk（优先选择同 CWE 类别的安全变体）

这一层教会模型将漏洞描述与漏洞代码关联起来。

**第二层：代码→代码三元组**

- **Anchor**：某个漏洞代码 Chunk
- **Positive**：同 CWE 类别的另一个漏洞代码 Chunk
- **Negative**：安全代码 Chunk

这一层教会模型将相似类型的漏洞代码聚类在一起。

**CWE 描述库**：内置 10 个常见 CWE 的标准描述（CWE-78, CWE-119, CWE-120, CWE-121, CWE-122, CWE-134, CWE-190, CWE-401, CWE-416, CWE-476），用于构建高质量的 anchor 文本。

### 7.2 Hard Negative Mining

Hard negative（困难负样本）是对比学习效果的关键。系统按优先级选择负样本：

1. **同 CWE 安全变体**（最高优先级）：与 positive 属于同一 CWE 类别但标记为 SAFE 的代码。例如，对于 CWE-122 的 `malloc` 漏洞，选择包含 `malloc` 但有正确边界检查的安全代码。这是最有价值的负样本，因为它迫使模型学习"有漏洞"和"安全"之间的细微差异。

2. **结构相似的安全代码**（中等优先级）：AST 节点类型集合与 positive 有交集的安全 Chunk。例如，都包含 `call_expression` 和 `if_statement`，但一个有漏洞一个安全。

3. **随机安全代码**（兜底）：从所有安全 Chunk 中随机采样。

每个 positive 默认生成 `num_hard_negatives=3` 个负样本，可通过配置调整。

### 7.3 对比学习训练（MultipleNegativesRankingLoss）

**训练框架**：使用 `sentence-transformers` 的训练 API。

**损失函数**：`MultipleNegativesRankingLoss`（MNRL）。这是对比学习的标准选择：

- 每个 batch 中，anchor-positive 对作为正样本
- 同 batch 内其他样本的 positive 和 negative 自动作为额外负样本（in-batch negatives）
- 这意味着实际的负样本数量远大于显式提供的 hard negatives，训练效率更高

**FinetuneConfig 默认配置**（适配 8-16GB GPU）：

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `batch_size` | `16` | 适配 8-16GB 显存 |
| `epochs` | `3` | 小数据集通常 3-5 轮足够 |
| `learning_rate` | `2e-5` | 标准微调学习率 |
| `warmup_ratio` | `0.1` | 前 10% 步数线性预热 |
| `fp16` | `True` | 混合精度训练，节省显存 |
| `max_seq_length` | `512` | 代码片段最大长度 |

**训练流程**：

1. 离线加载 base model（设置 `HF_HUB_OFFLINE=1`）
2. 将 `Triplet` 转换为 `InputExample(texts=[anchor, positive, negative])`
3. 构建 `DataLoader`（shuffle=True）
4. 使用 MNRL 损失函数训练
5. 可选：按 `eval_split` 比例划分验证集，使用 `TripletEvaluator` 监控训练效果
6. 保存到 `output_dir`，格式与 sentence-transformers 标准一致

**输出兼容性**：微调后的模型目录可以直接作为 `RetrievalConfig.model_path` 使用，无需任何转换步骤。

### 7.4 模型对比评估（compare）

`compare` 命令提供 base model 与 finetuned model 的并排对比：

1. 加载评估数据集
2. 解析所有样本，生成 Chunk
3. 为每个漏洞样本构建检索 gold item（查询 = 漏洞描述，相关文档 = 该漏洞函数的 Chunk）
4. 分别用 base model 和 finetuned model 构建索引并执行检索
5. 计算两组检索指标
6. 输出对比表：

```
Metric               Base         Finetuned    Delta
--------------------------------------------------------
MRR                  0.4500       0.7200       +0.2700
Recall@5             0.6000       0.8500       +0.2500
NDCG@10              0.5200       0.7800       +0.2600
```

## 8. 项目目录结构速查

```
graduation project/
│
├── mmrag/                              # 主包
│   ├── __init__.py                     # 版本号 (0.1.0)
│   │
│   ├── parsing/                        # 第一层：解析
│   │   ├── __init__.py                 # 公开 API 导出
│   │   ├── models.py                   # SourceLocation, ASTNode, FunctionInfo, CFG, Chunk, Slice...
│   │   ├── ast_parser.py              # Tree-sitter AST 解析 + 函数提取
│   │   ├── cfg_builder.py             # 控制流图构建
│   │   ├── slicer.py                  # 前向/后向程序切片 + DEF/USE 分析
│   │   ├── chunker.py                 # RAG 分块（函数级 + 块级）
│   │   └── __main__.py                # CLI: python -m mmrag.parsing
│   │
│   ├── retrieval/                      # 第二层：检索
│   │   ├── __init__.py
│   │   ├── models.py                   # RetrievalConfig, RetrievalResult, MetadataFilter, IndexStats
│   │   ├── tokenizer.py              # C/C++ 代码感知分词器
│   │   ├── bm25_index.py             # BM25Okapi 稀疏检索
│   │   ├── embedding_index.py        # sentence-transformers 稠密检索
│   │   ├── fusion.py                 # RRF 倒数排名融合
│   │   ├── retriever.py              # 统一检索器（BM25 + Embedding + RRF）
│   │   └── __main__.py                # CLI: python -m mmrag.retrieval
│   │
│   ├── reasoning/                      # 第三层：推理
│   │   ├── __init__.py
│   │   ├── models.py                   # Verdict, AttackArgument, DefenseArgument, JudgeVerdict...
│   │   ├── llm_backend.py            # GGUF 模型加载 + MockLLMBackend
│   │   ├── grammars.py               # GBNF 约束解码文法（Attacker/Defender/Judge）
│   │   ├── prompts.py                # 5 个 prompt 构建函数
│   │   ├── agents.py                 # AttackerAgent, DefenderAgent, JudgeAgent
│   │   ├── evidence.py               # 危险 API 检测 + CFG 摘要 + 路径验证
│   │   ├── orchestrator.py           # VulnerabilityAnalyzer 流水线编排器
│   │   └── __main__.py                # CLI: python -m mmrag.reasoning
│   │
│   ├── benchmark/                      # 评估基准框架
│   │   ├── __init__.py
│   │   ├── models.py                   # BenchmarkSample, VulnLabel, DetectionMetrics...
│   │   ├── dataset.py                 # JSONL + Juliet 数据集加载器
│   │   ├── metrics.py                 # Recall@K, Precision@K, MRR, NDCG, F1, IoU
│   │   ├── evaluator.py              # BenchmarkEvaluator 评估编排器
│   │   └── __main__.py                # CLI: python -m mmrag.benchmark
│   │
│   └── finetune/                       # Embedding 微调
│       ├── __init__.py
│       ├── models.py                   # Triplet, FinetuneConfig, FinetuneResult
│       ├── triplet_gen.py             # 三元组生成 + Hard Negative Mining
│       ├── trainer.py                 # EmbeddingFinetuner（MNRL 对比学习）
│       └── __main__.py                # CLI: python -m mmrag.finetune
│
├── tests/                              # 测试套件（153 个测试，无需 GPU）
│   ├── conftest.py                    # 共享 fixtures
│   ├── fixtures/
│   │   ├── sample.c                   # 测试用 C 源码（8 个函数）
│   │   ├── sample_broken.c            # 语法错误的 C 源码（容错测试）
│   │   └── benchmark_sample.jsonl     # 6 个评估样本（3 vulnerable + 3 safe）
│   ├── test_parser.py
│   ├── test_cfg.py
│   ├── test_chunker.py
│   ├── test_slicer.py
│   ├── test_bm25_index.py
│   ├── test_embedding_index.py
│   ├── test_fusion.py
│   ├── test_tokenizer.py
│   ├── test_retriever.py
│   ├── test_agents.py
│   ├── test_evidence.py
│   ├── test_orchestrator.py
│   ├── test_prompts.py
│   ├── test_reasoning_models.py
│   ├── test_robustness.py
│   ├── test_benchmark.py
│   └── test_finetune.py
│
├── doc/
│   ├── architecture.md                # 架构概述
│   ├── explanation.md                 # 详细技术说明
│   └── structure.md                   # 本文档
│
├── pyproject.toml                     # 项目配置与依赖
└── README.md                          # 使用指南与 FAQ
```

## 9. 使用流程

### 9.1 解析 → 索引 → 查询 → 分析 完整流程

```bash
# 1. 解析 C/C++ 文件，查看 AST、CFG、Chunk 信息
python -m mmrag.parsing file.c --output text

# 2. 索引代码库（BM25 必选，Embedding 可选）
python -m mmrag.retrieval index file.c --bm25-path ./index/bm25.pkl
# 带 Embedding：
python -m mmrag.retrieval index file.c --bm25-path ./index/bm25.pkl --model-path ./models/codefuse

# 3. 查询相似代码
python -m mmrag.retrieval query "strcpy buffer overflow" --mode bm25 --bm25-path ./index/bm25.pkl
# 混合查询：
python -m mmrag.retrieval query "strcpy buffer overflow" --mode fused --model-path ./models/codefuse

# 4. 漏洞分析（需要 GGUF 模型）
python -m mmrag.reasoning analyze file.c --model-path ./models/qwen2.5-coder-32b.Q4_K_M.gguf --output text
# 带检索上下文：
python -m mmrag.reasoning analyze file.c --model-path ./models/qwen.gguf --bm25-path ./index/bm25.pkl
```

### 9.2 评估基准使用流程

```bash
# 1. 将 Juliet Test Suite 转换为 JSONL 格式
python -m mmrag.benchmark convert --input /path/to/juliet --output dataset.jsonl --format juliet
# 可选：只转换特定 CWE
python -m mmrag.benchmark convert --input /path/to/juliet --output dataset.jsonl --cwe-filter CWE-122 CWE-78

# 2. 纯检索评估（不需要 LLM，快速迭代）
python -m mmrag.benchmark evaluate --dataset dataset.jsonl --mode retrieval --model-path ./models/codefuse

# 3. 端到端检测评估（需要 GGUF 模型）
python -m mmrag.benchmark evaluate --dataset dataset.jsonl --mode detection --llm-path ./models/qwen.gguf

# 4. 全量评估（检索 + 检测）
python -m mmrag.benchmark evaluate --dataset dataset.jsonl --mode all --model-path ./models/codefuse --llm-path ./models/qwen.gguf

# 5. 导出报告
python -m mmrag.benchmark evaluate --dataset dataset.jsonl --mode all --output json --output-file report.json
```

### 9.3 Embedding 微调使用流程

```bash
# 1. 从评估数据集生成训练三元组
python -m mmrag.finetune generate-triplets --dataset dataset.jsonl --output triplets.jsonl --num-hard-negatives 3

# 2. 微调 Embedding 模型
python -m mmrag.finetune train \
    --triplets triplets.jsonl \
    --base-model ./models/codefuse \
    --output-dir ./finetuned_model \
    --epochs 3 \
    --batch-size 16 \
    --learning-rate 2e-5 \
    --fp16

# 3. 对比 base model 与微调后模型的检索效果
python -m mmrag.finetune compare \
    --base-model ./models/codefuse \
    --finetuned ./finetuned_model \
    --dataset dataset.jsonl

# 4. 使用微调后的模型进行检索（直接替换 model-path）
python -m mmrag.retrieval index file.c --model-path ./finetuned_model --bm25-path ./index/bm25.pkl
python -m mmrag.retrieval query "buffer overflow" --mode fused --model-path ./finetuned_model
```
