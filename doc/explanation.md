                                                                                                                                                                                                                                                                       
  ---                                                                                                                                                                                                                                                                       
  MM-RAG: Multi-Modal Enhanced RAG 代码漏洞智能检测系统                                                                                                                                                                                                                     
                                                                                                                                                                                                                                                                            
  技术设计与实现说明书                                                                                                                                                                                                                                                      
                                                                                                                                                                                                                                                                            
  ---
  一、系统概述

  MM-RAG 是一套面向 C/C++ 遗留代码的深层漏洞智能检测系统，专为复杂装备软件安全审计场景设计。系统采用"解析—检索—推理"三层架构，结合大语言模型（LLM）与检索增强生成（RAG）技术，通过 Actor-Critic 对抗辩论框架实现白盒化、可追溯的漏洞挖掘。

  1.1 核心设计目标

  系统围绕三项不可违背的硬性约束进行设计：

  约束一：物理行号保真。 检测出的每一个漏洞，其 Source→Sink 路径中的每一个节点，都必须精准映射回原始源代码的物理行号。系统禁止任何破坏代码结构的预处理操作（如宏展开、#include 内联），所有分析均在原始文本上进行。这一约束贯穿三层架构的每一个数据结构——从 Tree-sitter
  解析产生的 ASTNode 到最终 VulnerabilityReport 中的 SourceSinkPoint，每个对象都携带 1-indexed 的物理行号。

  约束二：本地离线运行。 系统部署于涉密局域网，完全断网运行。基座模型为 Qwen2.5-Coder-32B（GGUF 量化格式），嵌入模型为 CodeFuse-CGE（本地加载）。所有依赖均可通过离线 wheel
  包安装，代码中通过环境变量（HF_HUB_OFFLINE=1、TRANSFORMERS_OFFLINE=1、ANONYMIZED_TELEMETRY=False）和参数（local_files_only=True）双重防护，杜绝任何外部网络访问。

  约束三：白盒化证据链。 系统不仅给出"有漏洞/无漏洞"的判定，还必须输出完整的 Source→Sink 物理路径，以及 Attacker-Defender 对抗辩论的全部记录。审计人员可以逐行审查 LLM 的推理过程，判断其结论是否可信。

  1.2 系统架构总览

  ┌─────────────────────────────────────────────────────────────────┐
  │                        MM-RAG System                            │
  │                                                                 │
  │  ┌──────────────┐  ┌──────────────────┐  ┌───────────────────┐  │
  │  │  Phase 1     │  │  Phase 2         │  │  Phase 3          │  │
  │  │  解析层       │──│  检索层           │──│  推理层            │  │
  │  │  Parsing     │  │  Retrieval       │  │  Reasoning        │  │
  │  │              │  │                  │  │                   │  │
  │  │ Tree-sitter  │  │ BM25 (稀疏)      │  │ Attacker Agent    │  │
  │  │ AST Parser   │  │ Embedding (稠密)  │  │ Defender Agent    │  │
  │  │ CFG Builder  │  │ RRF Fusion       │  │ Judge Agent       │  │
  │  │ Slicer       │  │                  │  │ GBNF Constrained  │  │
  │  │ Chunker      │  │                  │  │ Decoding          │  │
  │  └──────────────┘  └──────────────────┘  └───────────────────┘  │
  │                                                                 │
  │  基座模型: Qwen2.5-Coder-32B (GGUF)    推理框架: llama-cpp-python │
  │  嵌入模型: CodeFuse-CGE (本地)          向量存储: NumPy + Pickle   │
  └─────────────────────────────────────────────────────────────────┘

  1.3 项目目录结构

  graduation project/
  ├── pyproject.toml                  # 项目配置与依赖声明
  ├── mmrag/
  │   ├── __init__.py
  │   ├── parsing/                    # Phase 1: 解析层
  │   │   ├── models.py              #   数据模型 (ASTNode, CFG, Slice, Chunk 等)
  │   │   ├── ast_parser.py          #   Tree-sitter 解析与函数提取
  │   │   ├── cfg_builder.py         #   过程内控制流图构建
  │   │   ├── slicer.py              #   前向/后向程序切片
  │   │   ├── chunker.py             #   RAG 导向的代码分块
  │   │   └── __main__.py            #   CLI: python -m mmrag.parsing
  │   ├── retrieval/                  # Phase 2: 检索层
  │   │   ├── models.py              #   检索配置与结果模型
  │   │   ├── tokenizer.py           #   C/C++ 感知分词器
  │   │   ├── bm25_index.py          #   BM25 稀疏索引
  │   │   ├── embedding_index.py     #   稠密向量索引
  │   │   ├── fusion.py              #   RRF 融合算法
  │   │   ├── retriever.py           #   统一检索器
  │   │   └── __main__.py            #   CLI: python -m mmrag.retrieval
  │   └── reasoning/                  # Phase 3: 推理层
  │       ├── models.py              #   推理模型 (Verdict, DebateRecord 等)
  │       ├── llm_backend.py         #   LLM 推理后端 (GGUF + GPU 守卫)
  │       ├── grammars.py            #   GBNF 约束解码语法
  │       ├── prompts.py             #   Prompt 模板 (5 轮辩论)
  │       ├── agents.py              #   三智能体 (Attacker/Defender/Judge)
  │       ├── evidence.py            #   证据链构建与验证
  │       ├── orchestrator.py        #   辩论编排器
  │       └── __main__.py            #   CLI: python -m mmrag.reasoning
  ├── tests/                          # 测试套件 (114 个测试)
  │   ├── fixtures/
  │   │   ├── sample.c               #   标准测试文件
  │   │   └── sample_broken.c        #   容错性测试文件
  │   ├── test_parser.py
  │   ├── test_cfg.py
  │   ├── test_slicer.py
  │   ├── test_chunker.py
  │   ├── test_robustness.py
  │   ├── test_tokenizer.py
  │   ├── test_bm25_index.py
  │   ├── test_embedding_index.py
  │   ├── test_fusion.py
  │   ├── test_retriever.py
  │   ├── test_reasoning_models.py
  │   ├── test_evidence.py
  │   ├── test_prompts.py
  │   ├── test_agents.py
  │   └── test_orchestrator.py
  └── doc/
      └── architecture.md

  ---
  二、Phase 1：解析层 (Parsing Layer)

  解析层是整个系统的基座，负责将原始 C/C++ 源代码转化为结构化的中间表示，同时严格保持物理行号的一一对应关系。

  2.1 设计原则

  选择 Tree-sitter 而非 Clang AST 作为解析器，核心原因有三：

  1. 容错性：Tree-sitter 是增量式解析器，即使源代码存在语法错误（缺少头文件、未闭合大括号、未知宏），也能产出部分正确的 AST，而非直接报错退出。这对工业级遗留代码至关重要。
  2. 行号保真：Tree-sitter 产出的是具体语法树（CST），每个节点直接对应源代码中的字节范围，不存在任何中间变换。
  3. 零预处理：系统直接解析原始文本，不执行 #include 展开或宏替换，确保"所见即所得"。

  2.2 核心数据模型

  所有数据模型使用 Pydantic BaseModel 定义，支持 JSON 序列化/反序列化。

  SourceLocation / SourceRange：物理位置的基础表示。SourceLocation 包含 line（1-indexed）和 column。SourceRange 包含起止位置和字节偏移。Tree-sitter 返回 0-indexed 行号，系统在 ast_parser.py 的 _make_source_range() 函数中执行唯一一次 +1 转换，此后所有下游组件均使用
  1-indexed 行号。

  ASTNode：Tree-sitter 节点的 Python 表示。字段包括 node_type（如 "if_statement"、"call_expression"）、field_name（在父节点中的角色，如 "condition"、"body"）、source_range、text（原始源代码文本）、is_named、is_missing（标记解析错误节点）、children（递归子节点列表）。

  FunctionInfo：提取的函数信息。包含 name、return_type、parameters: list[ParameterInfo]、source_range（整个函数的行范围）、body_range（函数体的行范围）、signature_text（原始签名文本）、ast（完整的 AST 子树）。

  CFG 相关模型：BasicBlock 包含 block_id、statements: list[ASTNode]、predecessors、successors。CFGEdge 包含 source_id、target_id、kind（10 种边类型：UNCONDITIONAL、TRUE_BRANCH、FALSE_BRANCH、CASE、DEFAULT、BACK_EDGE、BREAK、CONTINUE、GOTO、RETURN）。CFG 包含
  entry_block_id、exit_block_id、blocks、edges、warnings。

  Slice：程序切片结果。包含 direction（BACKWARD/FORWARD）、criterion（行号+变量名）、included_lines（切片包含的物理行号列表）、statements（对应的 AST 节点）、source_text（切片对应的原始代码文本）。

  Chunk：面向 RAG 检索的代码块。包含 chunk_id（格式：file:function:startline-endline）、kind（FUNCTION/BLOCK/SLICE）、text（原始代码）、line_count、ast_node_types（块内出现的 AST 节点类型列表，用于下游过滤）、metadata（可包含 has_errors 标记）。

  2.3 AST 解析器 (ast_parser.py)

  语言检测：通过文件扩展名自动识别语言。.c/.h → C，.cpp/.cc/.cxx/.hpp → C++。

  解析流程：parse_file(file_path, language?) → 读取文件字节 → 创建 Tree-sitter Parser → 解析为 tree → 递归转换为 ASTNode 树 → 提取函数列表 → 返回 (root, functions, source_bytes)。

  函数提取：extract_functions() 对 AST 进行广度优先遍历，查找所有 function_definition 节点。对每个函数，提取函数名（通过递归查找 declarator 中最深的 identifier）、返回类型、参数列表、函数体范围、签名文本。

  错误收集：collect_errors() 遍历 AST，收集所有 ERROR、MISSING 节点以及 is_missing=True 的节点，返回人类可读的错误描述列表。

  2.4 控制流图构建器 (cfg_builder.py)

  算法：递归下降遍历函数体 AST，为每种语句类型构建对应的 CFG 结构。

  入口：build_cfg(function: FunctionInfo) → CFG。创建 ENTRY 和 EXIT 两个特殊块，然后从函数体的 compound_statement 开始递归处理。

  语句分发：_process_statement(node, current_block_id) 根据 node_type 分发：

  - expression_statement、declaration → 追加到当前块，fallthrough
  - return_statement → 追加到当前块，添加 RETURN 边到 EXIT，返回 None（无后继）
  - if_statement → 条件追加到当前块，创建 then 块和 join 块，TRUE_BRANCH 边到 then，处理 else_clause（Tree-sitter 将 else 包装在 else_clause 节点中，需要解包），FALSE_BRANCH 边到 else 或 join
  - while_statement → 创建条件块、循环体块、join 块，TRUE_BRANCH 到体，FALSE_BRANCH 到 join，体末尾 BACK_EDGE 回条件块
  - for_statement → 初始化追加到当前块，创建条件块、体块、更新块、join 块，体末尾到更新块，更新块 BACK_EDGE 回条件块
  - do_statement → 先执行体，再检查条件，TRUE_BRANCH 回体（这是 do-while 的语义）
  - switch_statement → 条件追加到当前块，遍历 body 中的 case_statement 节点（Tree-sitter 中 default 也是 case_statement，通过是否有 value 字段区分），为每个 case 创建块并添加 CASE/DEFAULT 边，处理 fall-through
  - goto_statement → 提取标签名，如果标签已注册则添加 GOTO 边，否则加入 pending 列表
  - labeled_statement → 注册标签到块映射，创建新块
  - break_statement → BREAK 边到 break 目标栈顶
  - continue_statement → CONTINUE 边到 continue 目标栈顶

  容错性（约束 A）：_process_statement 的默认分支处理所有未识别的节点类型（包括 ERROR、MISSING、preproc_ifdef 等），将其作为不透明的单行语句追加到当前块，unconditional fallthrough，并记录警告到 CFG.warnings。这确保了即使源代码有语法错误，CFG 构建也不会崩溃。

  后处理：解析完成后，解析 pending gotos（前向 goto 的目标标签在 goto 之后才出现）、计算每个块的 source_range、填充 predecessors/successors 邻接表。

  2.5 程序切片器 (slicer.py)

  算法：基于工作列表（worklist）的过程内数据流切片。

  DEF/USE 分析（约束 B：指针与结构体感知）：

  _extract_def_use(statement) 返回 (def_set, use_set)，其中集合元素是归一化的访问路径字符串：

  ┌───────────────────┬───────────────────────┬──────────────────────────┐
  │   C/C++ 表达式    │       DEF 集合        │         USE 集合         │
  ├───────────────────┼───────────────────────┼──────────────────────────┤
  │ x = expr          │ {"x"}                 │ {expr 中的标识符}        │
  ├───────────────────┼───────────────────────┼──────────────────────────┤
  │ *ptr = expr       │ {"*ptr", "ptr"}       │ {expr 中的标识符, "ptr"} │
  ├───────────────────┼───────────────────────┼──────────────────────────┤
  │ obj.field = expr  │ {"obj.field", "obj"}  │ {expr 中的标识符}        │
  ├───────────────────┼───────────────────────┼──────────────────────────┤
  │ ptr->field = expr │ {"ptr->field", "ptr"} │ {expr 中的标识符}        │
  ├───────────────────┼───────────────────────┼──────────────────────────┤
  │ arr[i] = expr     │ {"arr[]", "arr"}      │ {"i", expr 中的标识符}   │
  ├───────────────────┼───────────────────────┼──────────────────────────┤
  │ i++ / --j         │ {"i"} / {"j"}         │ {"i"} / {"j"}            │
  └───────────────────┴───────────────────────┴──────────────────────────┘

  归一化路径表示法："x"（简单变量）、"*ptr"（解引用）、"obj.field"（结构体字段）、"ptr->field"（指针字段）、"arr[]"（数组访问，下标擦除）。

  前缀匹配规则：切片匹配时使用前缀匹配——切片准则 "ptr" 会匹配 "ptr"、"ptr->field"、"ptr->other" 等所有以 ptr 为根的访问路径。这是保守但安全的策略，确保不遗漏漏洞相关的数据流。

  后向切片：从切片准则（行号+变量）出发，沿 CFG 反向遍历，追踪 USE→DEF 链。工作列表项为 (block_id, stmt_idx, variable, is_seed)，is_seed 标记区分种子语句（跳过自身）和后续传播（检查当前语句）。遇到空块时递归穿越到有语句的前驱块。

  前向切片：对称实现，追踪 DEF→USE 链。

  容错性：ERROR/MISSING 节点的 DEF/USE 返回空集，对切片透明。

  2.6 代码分块器 (chunker.py)

  两级分块策略：

  - Tier 1（函数级）：每个函数产生一个 FUNCTION 类型的 Chunk，包含完整函数代码。
  - Tier 2（语义块级）：对于超过 split_threshold（默认 30 行）的长函数，进一步拆分为 BLOCK 类型的 Chunk。拆分规则：每个复合语句（if/for/while/do/switch）独立成块；连续的简单语句（声明、表达式语句）按 max_simple_group（默认 15 行）分组。

  每个 Chunk 携带 ast_node_types 列表（块内出现的所有 AST 节点类型），供检索层进行元数据过滤。含 ERROR 节点的 Chunk 在 metadata 中标记 has_errors=true。

  2.7 容错性设计（约束 A）

  真实工业代码经常缺少头文件、包含复杂嵌套宏、存在不完整的翻译单元。系统在每一层都实现了防御性编程：

  - ast_parser.py：ERROR/MISSING 节点正常转换为 ASTNode，携带 is_missing 标记，错误信息收集到 ParseResult.errors。
  - cfg_builder.py：未识别节点类型走默认 fallback 分支，作为不透明语句 fallthrough，记录警告。
  - slicer.py：ERROR 节点的 DEF/USE 返回空集，不影响切片传播。
  - chunker.py：ERROR 节点原样包含在 Chunk 中，metadata 标记 has_errors。

  测试文件 sample_broken.c 包含缺失分号、未闭合大括号、#ifdef 块等错误，验证系统在所有层都不抛异常。

  2.8 宏调用处理（约束 C）

  严格执行"所见即所得"策略。Tree-sitter 是具体语法树解析器，宏函数调用（如 SAFE_FREE(buf)）被解析为普通的 call_expression，与 free(buf) 在 AST 结构上完全一致。系统不做任何宏展开或猜测，原始行号自然保持。#define 指令被解析为 preproc_def 节点，在 CFG 构建时走默认
  fallback 分支。

  ---
  三、Phase 2：检索层 (Retrieval Layer)

  检索层实现 BM25（稀疏）与 Embedding（稠密）异构双路检索，通过 RRF 算法融合，为推理层提供相似代码模式的上下文。

  3.1 C/C++ 感知分词器 (tokenizer.py)

  通用的 BM25 分词器无法处理代码特有的命名约定和运算符。系统实现了专用的 C/C++ 分词管线：

  处理流程：
  1. 剥离注释和字符串字面量：用正则表达式匹配 //、/* */、"..."、'...'，替换为空白。这避免了注释内容干扰检索。
  2. 保护多字符运算符：将 -> 替换为占位符 _OP_ARROW_，:: 替换为 _OP_SCOPE_，以此类推（共 22 种运算符）。这防止运算符在后续分割时被拆散。
  3. 按非字母数字字符分割：re.split(r'[^a-zA-Z0-9_]+', text)。
  4. camelCase / snake_case 拆分：maxBufferSize → ["maxbuffersize", "max", "buffer", "size"]（保留原始复合词 + 拆分后的子词）。max_buffer_size → ["max_buffer_size", "max", "buffer", "size"]。
  5. 小写化。
  6. 还原运算符占位符：_OP_ARROW_ → "op_arrow"。
  7. 过滤单字符 token（除 C 关键字 if、do 外）。

  关键词保留：分词器内置了 C/C++ 关键字表和危险 API 名称表（malloc、strcpy、sprintf、gets、system 等），这些 token 在检索中携带重要的漏洞信号。

  3.2 BM25 稀疏索引 (bm25_index.py)

  基于 rank_bm25.BM25Okapi 实现。

  构建：build(chunks) → 对每个 Chunk 的 text 执行 C/C++ 分词 → 构建 BM25Okapi 索引。

  查询：query(query_text, top_k, filters?) → 分词查询文本 → get_scores() 获取所有文档的 BM25 分数 → 如果有元数据过滤器，将不匹配文档的分数置零 → argsort 取 top-k。

  元数据过滤：支持按 file_paths、function_names、kinds、ast_node_types 过滤。过滤在评分之后执行（post-scoring），通过构建 0/1 掩码向量与分数向量逐元素相乘实现。

  持久化：通过 pickle 序列化 chunk_ids、chunks 字典、分词后的语料库。加载时重建 BM25Okapi 对象。

  3.3 稠密向量索引 (embedding_index.py)

  基于 NumPy 矩阵运算实现（替代 ChromaDB，避免 C++ 编译依赖）。

  模型加载（约束 D/E/F）：

  # 约束 E: 严格离线加载
  os.environ["HF_HUB_OFFLINE"] = "1"
  os.environ["TRANSFORMERS_OFFLINE"] = "1"
  model = SentenceTransformer(
      config.model_path,          # 必须是本地绝对路径
      device=device,              # 约束 F: 动态设备选择
      trust_remote_code=False,
      local_files_only=True,
  )

  # 约束 F: GPU 自动感知
  device = "cuda" if torch.cuda.is_available() else "cpu"

  config.model_path 为空时直接抛出 ValueError，绝不回退到在线下载。

  构建：build(chunks) → 分批编码（batch_size=64）→ L2 归一化 → 拼接为 NumPy 矩阵。

  查询：query(query_text, top_k, filters?) → 编码查询向量 → 矩阵乘法计算余弦相似度（向量已归一化，内积即余弦）→ 元数据过滤 → argsort 取 top-k。

  持久化：通过 pickle 序列化 chunk_ids、chunks 字典、embedding 矩阵。

  3.4 RRF 融合算法 (fusion.py)

  Reciprocal Rank Fusion (RRF) 将两路检索结果合并为统一排序：

  score(d) = bm25_weight / (rrf_k + rank_bm25(d)) + embedding_weight / (rrf_k + rank_emb(d))

  其中 rrf_k=60 是标准常数，用于平滑排名差异。

  处理逻辑：
  - 遍历 BM25 结果，按 rank 计算贡献分
  - 遍历 Embedding 结果，累加贡献分
  - 仅出现在一路结果中的文档，另一路贡献为 0
  - 按融合分数降序排列，取 top-k
  - 支持可配置的权重（bm25_weight、embedding_weight），允许调节两路的相对重要性

  3.5 统一检索器 (retriever.py)

  Retriever 类编排完整的检索流程：

  - index(chunks) → 构建 BM25 索引 + 构建 Embedding 索引（如果提供了 model_path）
  - query(query_text, top_k, filters?) → BM25 查询（fetch_k = top_k × multiplier）+ Embedding 查询 → RRF 融合 → 返回 top-k
  - query_bm25_only() / query_embedding_only() → 单路查询
  - save() / load() → 持久化/加载索引

  当未提供嵌入模型路径时，系统自动降级为纯 BM25 检索，不影响功能完整性。

  3.6 离线安全约束

  约束 D（遥测关闭）：虽然最终实现中用 NumPy 替代了 ChromaDB（因 Python 3.14 编译兼容性），但代码中保留了遥测关闭的模式，作为未来切换回 ChromaDB 时的防护。

  约束 E（严格离线模型加载）：双重防护——环境变量 HF_HUB_OFFLINE=1 + TRANSFORMERS_OFFLINE=1 阻断 HuggingFace Hub 访问，local_files_only=True 参数阻断 SentenceTransformer 的自动下载。

  约束 F（动态设备选择）：device="auto" 时通过 torch.cuda.is_available() 自动检测 GPU，在索引海量代码块时充分利用 GPU 加速向量计算。

  ---
  四、Phase 3：推理层 (Reasoning Layer)

  推理层是系统的核心智能组件，实现基于 Actor-Critic 博弈框架的对抗辩论式漏洞分析。

  4.1 Actor-Critic 对抗辩论框架

  系统设计了三个角色的智能体：

  Attacker（攻击者/Actor）：扮演安全审计员，主张代码存在漏洞。职责：识别漏洞类型（CWE 编号）、定位 Source（危险数据源头）和 Sink（危险操作点）、追踪完整的数据流路径、给出置信度评分。

  **Defender（防御者/Critic
              
● 接着上次的位置继续。                                                                                                                                                                                                                                                      
                                                                                                                                                                                                                                                                          
  ---
  1.3 项目目录结构                                                                                                                                                                                                                                                          
   
  graduation project/                                                                                                                                                                                                                                                       
  ├── pyproject.toml                 # 项目配置与依赖声明   
  ├── mmrag/
  │   ├── __init__.py
  │   ├── parsing/                   # Phase 1: 解析层
  │   │   ├── __init__.py
  │   │   ├── models.py              # 解析层数据模型
  │   │   ├── ast_parser.py          # Tree-sitter AST 解析与函数提取
  │   │   ├── cfg_builder.py         # 过程内控制流图构建
  │   │   ├── slicer.py              # 前向/后向程序切片
  │   │   ├── chunker.py             # RAG 导向的代码分块
  │   │   └── __main__.py            # CLI: python -m mmrag.parsing
  │   ├── retrieval/                 # Phase 2: 检索层
  │   │   ├── __init__.py
  │   │   ├── models.py              # 检索层数据模型
  │   │   ├── tokenizer.py           # C/C++ 感知分词器
  │   │   ├── bm25_index.py          # BM25 稀疏索引
  │   │   ├── embedding_index.py     # 稠密向量索引
  │   │   ├── fusion.py              # RRF 融合算法
  │   │   ├── retriever.py           # 统一检索器
  │   │   └── __main__.py            # CLI: python -m mmrag.retrieval
  │   └── reasoning/                 # Phase 3: 推理层
  │       ├── __init__.py
  │       ├── models.py              # 推理层数据模型
  │       ├── llm_backend.py         # LLM 推理后端 (GGUF + GPU 守卫)
  │       ├── grammars.py            # GBNF 约束解码语法
  │       ├── prompts.py             # Prompt 模板
  │       ├── evidence.py            # 证据链构建与验证
  │       ├── agents.py              # Attacker/Defender/Judge 智能体
  │       ├── orchestrator.py        # 辩论编排器
  │       └── __main__.py            # CLI: python -m mmrag.reasoning
  ├── tests/
  │   ├── conftest.py
  │   ├── fixtures/
  │   │   ├── sample.c               # 标准测试用例
  │   │   └── sample_broken.c        # 容错性测试用例
  │   ├── test_parser.py             # 解析器测试 (8 tests)
  │   ├── test_cfg.py                # CFG 构建测试 (7 tests)
  │   ├── test_slicer.py             # 切片器测试 (8 tests)
  │   ├── test_chunker.py            # 分块器测试 (8 tests)
  │   ├── test_robustness.py         # 容错性测试 (6 tests)
  │   ├── test_tokenizer.py          # C/C++ 分词测试 (13 tests)
  │   ├── test_bm25_index.py         # BM25 索引测试 (8 tests)
  │   ├── test_embedding_index.py    # 嵌入索引测试 (7 tests)
  │   ├── test_fusion.py             # RRF 融合测试 (6 tests)
  │   ├── test_retriever.py          # 统一检索器测试 (6 tests)
  │   ├── test_reasoning_models.py   # 推理模型测试 (7 tests)
  │   ├── test_evidence.py           # 证据链测试 (8 tests)
  │   ├── test_prompts.py            # Prompt 模板测试 (9 tests)
  │   ├── test_agents.py             # 智能体测试 (9 tests)
  │   └── test_orchestrator.py       # 编排器端到端测试 (4 tests)
  └── doc/
      └── architecture.md

  1.4 依赖清单

  ┌───────────────────────┬──────────────┬───────────────────────────┬────────────────────────────────────────────────┐
  │         包名          │   版本约束   │           用途            │                  离线部署说明                  │
  ├───────────────────────┼──────────────┼───────────────────────────┼────────────────────────────────────────────────┤
  │ tree-sitter           │ >=0.22,<0.26 │ Tree-sitter Python 绑定   │ 预编译 wheel                                   │
  ├───────────────────────┼──────────────┼───────────────────────────┼────────────────────────────────────────────────┤
  │ tree-sitter-c         │ >=0.21       │ C 语言语法包              │ 预编译 wheel                                   │
  ├───────────────────────┼──────────────┼───────────────────────────┼────────────────────────────────────────────────┤
  │ tree-sitter-cpp       │ >=0.22       │ C++ 语言语法包            │ 预编译 wheel                                   │
  ├───────────────────────┼──────────────┼───────────────────────────┼────────────────────────────────────────────────┤
  │ pydantic              │ >=2.0,<3.0   │ 数据模型与 JSON 序列化    │ 纯 Python                                      │
  ├───────────────────────┼──────────────┼───────────────────────────┼────────────────────────────────────────────────┤
  │ rank-bm25             │ >=0.2.2,<0.3 │ BM25 稀疏检索             │ 纯 Python                                      │
  ├───────────────────────┼──────────────┼───────────────────────────┼────────────────────────────────────────────────┤
  │ numpy                 │ >=1.22       │ 向量运算                  │ 预编译 wheel                                   │
  ├───────────────────────┼──────────────┼───────────────────────────┼────────────────────────────────────────────────┤
  │ sentence-transformers │ >=2.2.0,<4.0 │ 嵌入模型加载              │ 预编译 wheel                                   │
  ├───────────────────────┼──────────────┼───────────────────────────┼────────────────────────────────────────────────┤
  │ llama-cpp-python      │ >=0.2.0      │ GGUF 推理 + GBNF 约束解码 │ 可选依赖 pip install mmrag[gpu]，需 C++ 编译器 │
  └───────────────────────┴──────────────┴───────────────────────────┴────────────────────────────────────────────────┘

  ---
  二、Phase 1：解析层（Parsing Layer）

  解析层是整个系统的基座，负责将原始 C/C++ 源文件转化为结构化的中间表示。它的核心职责是：在保持物理行号绝对保真的前提下，提取函数、构建控制流图、执行程序切片、生成 RAG 检索所需的代码块。

  2.1 AST 解析器（ast_parser.py）

  2.1.1 设计选择：为什么是 Tree-sitter 而非 Clang

  系统选择 Tree-sitter 而非 Clang AST 作为解析前端，原因如下：

  1. 容错性：Tree-sitter 是增量解析器，即使源文件存在语法错误（缺少头文件、未定义的宏），也能产生部分正确的语法树，错误区域标记为 ERROR 或 MISSING 节点。Clang 在缺少头文件时会直接报错退出。
  2. 行号保真：Tree-sitter 解析的是具体语法树（CST），每个节点直接对应原始文本的字节范围，不存在任何预处理变换。
  3. 零外部依赖：Tree-sitter 的 C/C++ 语法包以预编译 wheel 分发，无需安装 LLVM/Clang 工具链。
  4. 宏调用透明：SAFE_FREE(ptr) 这样的宏调用在 Tree-sitter 中被解析为普通的 call_expression，与 free(ptr) 的处理方式完全一致——这正是"所见即所得"原则的体现。

  2.1.2 行号转换：唯一的转换点

  Tree-sitter 返回的行号是 0-indexed 的 (row, column) 元组。整个系统中，只有一个地方执行 0→1 的转换：

  def _make_source_range(node: Node) -> SourceRange:
      return SourceRange(
          start=SourceLocation(line=node.start_point[0] + 1, column=node.start_point[1]),
          end=SourceLocation(line=node.end_point[0] + 1, column=node.end_point[1]),
          start_byte=node.start_byte,
          end_byte=node.end_byte,
      )

  此后所有下游模块（CFG、Slicer、Chunker、Retriever、Reasoning）使用的行号均为 1-indexed 物理行号，与编辑器中看到的行号完全一致。

  2.1.3 AST 转换流程

  原始 .c/.cpp 文件
      │
      ▼ read_bytes()
  原始字节流 (bytes)
      │
      ▼ tree_sitter.Parser.parse(source)
  Tree-sitter 原生 Node 树
      │
      ▼ _node_to_ast(node, source) — 递归转换
  ASTNode 树 (Pydantic 模型, 可序列化为 JSON)
      │
      ▼ extract_functions(root, source)
  list[FunctionInfo] — 每个函数的名称、返回类型、参数、签名、AST 子树

  _node_to_ast 递归遍历 Tree-sitter 节点树，为每个节点创建 ASTNode 对象，保留：
  - node_type：节点类型（如 function_definition、if_statement、call_expression）
  - field_name：在父节点中的角色（如 body、condition、left、right）
  - source_range：精确的物理位置（行号、列号、字节偏移）
  - text：原始源代码文本
  - is_missing：Tree-sitter 标记的缺失节点（容错性标志）

  2.1.4 函数提取

  extract_functions 通过 BFS 遍历 AST 根节点，查找所有 function_definition 节点。对每个函数提取：
  - 函数名：通过 _find_deepest_identifier 递归查找 declarator 字段中的 identifier 节点
  - 返回类型：从 type 字段提取
  - 参数列表：遍历 parameter_list 中的 parameter_declaration 节点
  - 签名文本：从函数起始到函数体 { 之间的原始文本
  - 函数体范围：body 字段（compound_statement）的 SourceRange

  2.1.5 错误收集

  collect_errors 遍历整棵 AST，收集所有 ERROR、MISSING 节点以及 is_missing=True 的节点，生成人类可读的错误报告。这些错误不会阻止后续分析——系统会对有效部分继续处理。

  2.2 控制流图构建器（cfg_builder.py）

  2.2.1 算法概述

  CFG 构建采用递归下降法，对函数体内的每条语句按类型分派处理。核心数据结构：

  - BasicBlock：基本块，包含一组顺序执行的语句（statements: list[ASTNode]），以及前驱/后继列表
  - CFGEdge：有向边，携带类型标签（CFGEdgeKind）
  - Entry/Exit 块：每个 CFG 有且仅有一个入口块和一个出口块

  2.2.2 语句分派表

  _process_statement(node, current_block_id) 根据 node_type 分派：

  ┌──────────────────────────────────────────────┬───────────────────────────────────────────────────┬──────────────────────────────────────┐
  │                   节点类型                   │                     处理策略                      │             产生的边类型             │
  ├──────────────────────────────────────────────┼───────────────────────────────────────────────────┼──────────────────────────────────────┤
  │ expression_statement, declaration            │ 追加到当前块，顺序执行                            │ —                                    │
  ├──────────────────────────────────────────────┼───────────────────────────────────────────────────┼──────────────────────────────────────┤
  │ return_statement                             │ 追加到当前块，连接到 EXIT                         │ RETURN                               │
  ├──────────────────────────────────────────────┼───────────────────────────────────────────────────┼──────────────────────────────────────┤
  │ if_statement                                 │ 条件放入当前块，创建 then/else 分支块和 join 块   │ TRUE_BRANCH, FALSE_BRANCH            │
  ├──────────────────────────────────────────────┼───────────────────────────────────────────────────┼──────────────────────────────────────┤
  │ while_statement                              │ 创建条件块、循环体块、join 块                     │ TRUE_BRANCH, FALSE_BRANCH, BACK_EDGE │
  ├──────────────────────────────────────────────┼───────────────────────────────────────────────────┼──────────────────────────────────────┤
  │ for_statement                                │ 初始化在当前块，创建条件块、体块、更新块、join 块 │ TRUE_BRANCH, FALSE_BRANCH, BACK_EDGE │
  ├──────────────────────────────────────────────┼───────────────────────────────────────────────────┼──────────────────────────────────────┤
  │ do_statement                                 │ 先执行体，再检查条件                              │ TRUE_BRANCH(回到体), FALSE_BRANCH    │
  ├──────────────────────────────────────────────┼───────────────────────────────────────────────────┼──────────────────────────────────────┤
  │ switch_statement                             │ 为每个 case/default 创建分支块                    │ CASE, DEFAULT                        │
  ├──────────────────────────────────────────────┼───────────────────────────────────────────────────┼──────────────────────────────────────┤
  │ goto_statement                               │ 记录跳转，后处理阶段解析                          │ GOTO                                 │
  ├──────────────────────────────────────────────┼───────────────────────────────────────────────────┼──────────────────────────────────────┤
  │ labeled_statement                            │ 注册标签，创建新块                                │ UNCONDITIONAL                        │
  ├──────────────────────────────────────────────┼───────────────────────────────────────────────────┼──────────────────────────────────────┤
  │ break_statement                              │ 连接到 break 目标栈顶                             │ BREAK                                │
  ├──────────────────────────────────────────────┼───────────────────────────────────────────────────┼──────────────────────────────────────┤
  │ continue_statement                           │ 连接到 continue 目标栈顶                          │ CONTINUE                             │
  ├──────────────────────────────────────────────┼───────────────────────────────────────────────────┼──────────────────────────────────────┤
  │ compound_statement                           │ 递归处理子语句                                    │ —                                    │
  ├──────────────────────────────────────────────┼───────────────────────────────────────────────────┼──────────────────────────────────────┤
  │ 其他所有类型（含 ERROR, MISSING, preproc_*） │ 降级为不透明语句，追加到当前块，顺序执行          │ —                                    │
  └──────────────────────────────────────────────┴───────────────────────────────────────────────────┴──────────────────────────────────────┘

  最后一行是**容错性约束（Constraint A）**的核心实现：任何无法识别的节点类型都不会导致异常，而是被当作普通语句处理，并在 CFG.warnings 中记录警告。

  2.2.3 else_clause 展开

  Tree-sitter 的 C 语法将 else 分支包装在 else_clause 节点中。CFG 构建器在处理 if_statement 的 alternative 字段时，会自动展开 else_clause，提取其内部的实际语句（可能是 compound_statement 或嵌套的 if_statement）。

  2.2.4 switch/case 处理

  Tree-sitter-c 将 case 和 default 统一表示为 case_statement 节点，通过是否存在 value 字段来区分。CFG 构建器检查每个 case_statement：有 value 字段的创建 CASE 边，无 value 字段的创建 DEFAULT 边。Fall-through 通过相邻 case 块之间的 UNCONDITIONAL 边实现。

  2.2.5 后处理

  构建完成后执行三步后处理：
  1. 解析 goto：将 _pending_gotos 中的前向 goto 与已注册的标签块关联
  2. 计算块范围：根据每个块中语句的 SourceRange 计算块级别的范围
  3. 填充邻接表：遍历所有边，填充每个块的 predecessors 和 successors 列表

  2.3 程序切片器（slicer.py）

  2.3.1 切片算法

  切片器实现基于工作列表（worklist）的过程内数据流切片：

  后向切片（Backward Slice）：从切片准则（某行的某个变量）出发，沿 CFG 反向追踪所有影响该变量值的语句。

  工作列表初始化: [(seed_block, seed_idx, variable, is_seed=True)]

  while 工作列表非空:
      取出 (block_id, stmt_idx, var, is_seed)
      从 stmt_idx 向前扫描当前块:
          if 某语句 DEF 了 var:
              将该语句加入切片结果
              将该语句的所有 USE 变量加入工作列表
              停止扫描当前块
      if 当前块中未找到 DEF:
          将所有前驱块的最后一条语句加入工作列表
          (递归穿越空块，直到找到有语句的前驱)

  前向切片（Forward Slice）：对称操作，沿 CFG 正向追踪变量被使用的所有位置。

  2.3.2 指针与结构体感知的 DEF/USE 分析（Constraint B）

  这是切片器最关键的设计点。C/C++ 的赋值远不止简单的 x = expr，切片器必须正确处理复合左值：

  DEF 集合提取规则：

  ┌─────────────────────┬─────────────────────────┬──────────────────────────────────┐
  │      代码模式       │        DEF 集合         │               说明               │
  ├─────────────────────┼─────────────────────────┼──────────────────────────────────┤
  │ x = ...             │ {"x"}                   │ 简单标识符                       │
  ├─────────────────────┼─────────────────────────┼──────────────────────────────────┤
  │ *ptr = ...          │ {"*ptr", "ptr"}         │ 指针解引用，ptr 本身也被隐式使用 │
  ├─────────────────────┼─────────────────────────┼──────────────────────────────────┤
  │ obj.field = ...     │ {"obj.field", "obj"}    │ 结构体字段                       │
  ├─────────────────────┼─────────────────────────┼──────────────────────────────────┤
  │ ptr->field = ...    │ {"ptr->field", "ptr"}   │ 指针字段                         │
  ├─────────────────────┼─────────────────────────┼──────────────────────────────────┤
  │ arr[i] = ...        │ {"arr[]", "arr"}        │ 数组下标，i 进入 USE 集合        │
  ├─────────────────────┼─────────────────────────┼──────────────────────────────────┤
  │ ptr->arr[i].x = ... │ {"ptr->arr[].x", "ptr"} │ 嵌套访问，i 进入 USE             │
  ├─────────────────────┼─────────────────────────┼──────────────────────────────────┤
  │ i++, --j            │ {"i"} / {"j"}           │ 更新表达式                       │
  └─────────────────────┴─────────────────────────┴──────────────────────────────────┘

  归一化路径表示法：所有 DEF/USE 令牌使用统一的路径格式：
  - "x" — 简单变量
  - "*ptr" — 解引用指针
  - "obj.field" — 结构体字段
  - "ptr->field" — 指针字段
  - "arr[]" — 数组访问（下标擦除，因为不追踪具体值）

  前缀匹配规则：切片器在检查变量 v 是否在 DEF(s) 或 USE(s) 中时，使用前缀匹配："ptr" 匹配 "ptr"、"ptr->field"、"ptr->other"。这意味着对 ptr 的切片会包含所有触及 ptr 任何字段的语句——保守但对漏洞检测而言是安全的。

  ERROR 节点处理：对于 ERROR 或 MISSING 节点，_extract_def_use 返回空集 (∅, ∅)，使其对切片透明——不会被包含在切片中，除非它恰好在切片准则行上。

  2.3.3 空块穿越

  CFG 中经常存在空的 join 块（如 if/else 的汇合点）。切片器通过 _propagate_to_predecessors / _propagate_to_successors 递归穿越空块，直到找到包含语句的块。这确保了切片能正确穿越 if/else 分支——例如，从 return result 后向切片能追踪到所有分支中对 result 的赋值。

  2.4 代码分块器（chunker.py）

  分块器将解析后的函数转化为适合 RAG 检索的代码块（Chunk）。采用两级策略：

  Tier 1 — 函数级块：每个函数生成一个完整的 FUNCTION 类型 Chunk，包含函数全文。这是始终生成的基础块。

  Tier 2 — 语义块：对于超过 split_threshold（默认 30 行）的长函数，进一步拆分为语义块：
  - 每个控制流结构（if、for、while、do、switch）独立成块
  - 连续的简单语句（声明、表达式语句）按 max_simple_group（默认 15 行）分组
  - 每个语义块的 metadata["context"] 字段保存父函数的签名文本，为检索提供上下文

  每个 Chunk 携带的元数据：
  - chunk_id：格式为 {file_path}:{function_name}:{start_line}-{end_line}
  - kind：FUNCTION 或 BLOCK
  - ast_node_types：块内所有 AST 节点类型的排序列表（用于下游过滤）
  - metadata["has_errors"]：如果块内包含 ERROR/MISSING 节点则标记为 "true"

  ---
  三、Phase 2：检索层（Retrieval Layer）

  检索层实现 BM25（稀疏）与 Embedding（稠密）异构双路检索，通过 RRF 算法融合两路结果。它的职责是：给定一个查询（代码片段、变量名、函数签名或自然语言描述），从已索引的代码块中检索出最相关的上下文，供推理层使用。

  3.1 C/C++ 感知分词器（tokenizer.py）

  BM25 对代码的检索效果高度依赖分词质量。通用的英文分词器无法处理 C/C++ 的命名约定和运算符。系统实现了专用的代码分词管线：

  原始代码文本
      │
      ▼ 1. 剥离注释和字符串字面量
      │    正则: //行注释, /*块注释*/, "字符串", '字符'
      │    替换为空格，保持位置结构
      │
      ▼ 2. 保护多字符运算符
      │    -> 替换为 _OP_ARROW_
      │    :: 替换为 _OP_SCOPE_
      │    ==, !=, <=, >=, &&, ||, ++, -- 等同理
      │    (按长度降序替换，避免 <<= 被 << 先匹配)
      │
      ▼ 3. 按非字母数字字符分割
      │    re.split(r'[^a-zA-Z0-9_]+', text)
      │
      ▼ 4. 子分割 camelCase 和 snake_case
      │    maxBufferSize → ["maxbuffersize", "max", "buffer", "size"]
      │    max_buffer_size → ["max_buffer_size", "max", "buffer", "size"]
      │    (保留原始复合词 + 拆分后的子词)
      │
      ▼ 5. 全部小写化
      │
      ▼ 6. 还原运算符占位符
      │    _OP_ARROW_ → "op_arrow"
      │
      ▼ 7. 过滤单字符令牌
      │    (保留 C 关键字 "if", "do")
      │
      ▼ 最终令牌列表

  分词器保留了 C/C++ 关键字和危险 API 名称（malloc, free, strcpy, sprintf, gets, system 等），因为这些词汇携带强烈的漏洞信号。

  3.2 BM25 稀疏索引（bm25_index.py）

  基于 rank_bm25.BM25Okapi 实现，这是经典的 BM25 变体，考虑了词频（TF）、逆文档频率（IDF）和文档长度归一化。

  索引构建：
  tokenized_corpus = [tokenize_code(chunk.text) for chunk in chunks]
  bm25 = BM25Okapi(tokenized_corpus)

  查询流程：
  1. 对查询文本执行 tokenize_query（跳过注释/字符串剥离步骤）
  2. 调用 bm25.get_scores(query_tokens) 获取所有文档的 BM25 分数
  3. 如果有元数据过滤器，将不匹配文档的分数置零
  4. 取 top-k 个非零分数的文档

  元数据过滤：采用后评分过滤策略——先计算所有文档的 BM25 分数，再通过掩码向量将不满足过滤条件的文档分数置零。支持按 file_path、function_name、kind、ast_node_types 过滤。

  持久化：通过 pickle 序列化 chunk_ids、chunks（JSON 格式）和 tokenized_corpus。加载时重建 BM25Okapi 对象。

  3.3 稠密向量索引（embedding_index.py）

  使用 sentence-transformers 加载本地嵌入模型，将代码块编码为稠密向量，通过余弦相似度检索。

  离线安全约束：

  # Constraint D: 关闭遥测（原为 ChromaDB，现为通用防护）
  # Constraint E: 严格离线加载
  os.environ["HF_HUB_OFFLINE"] = "1"
  os.environ["TRANSFORMERS_OFFLINE"] = "1"

  model = SentenceTransformer(
      config.model_path,       # 必须是本地绝对路径
      device=device,
      trust_remote_code=False,  # 禁止执行不受信任的模型代码
      local_files_only=True,    # 禁止回退到 HuggingFace Hub
  )

  动态设备选择（Constraint F）：
  # config.device = "auto" 时自动检测
  import torch
  device = "cuda" if torch.cuda.is_available() else "cpu"

  索引构建：分批编码（embedding_batch_size=64），L2 归一化后存储为 NumPy 数组。

  查询流程：编码查询文本 → 与所有文档向量做点积（因已归一化，等价于余弦相似度）→ 应用过滤掩码 → 取 top-k。

  持久化：通过 pickle 序列化 chunk_ids、chunks、embeddings（NumPy 数组）。

  3.4 RRF 融合算法（fusion.py）

  Reciprocal Rank Fusion（RRF）是一种无需训练的排名融合方法，通过倒数排名加权合并多路检索结果：

  score(d) = w_bm25 / (k + rank_bm25(d)) + w_emb / (k + rank_emb(d))

  其中：
  - k = 60（标准常数，控制排名衰减速度）
  - w_bm25、w_emb 为可配置权重（默认均为 1.0）
  - 如果某文档只出现在一路结果中，另一路的贡献为 0

  RRF 的优势在于：它不依赖分数的绝对值（BM25 和余弦相似度的量纲完全不同），只依赖排名位置，因此天然适合异构检索融合。

  3.5 统一检索器（retriever.py）

  Retriever 类编排整个检索流程：

  query(query_text, top_k, filters)
      │
      ├── BM25Index.query(query_text, fetch_k = top_k × 3)
      │       → list[RetrievalResult] (source=BM25)
      │
      ├── EmbeddingIndex.query(query_text, fetch_k = top_k × 3)
      │       → list[RetrievalResult] (source=EMBEDDING)
      │
      └── reciprocal_rank_fusion(bm25_results, emb_results, top_k)
              → list[RetrievalResult] (source=FUSED)

  fetch_k = top_k × bm25_top_k_multiplier 确保每路检索返回足够多的候选，RRF 融合后再截断到 top_k。

  如果没有配置嵌入模型（model_path 为空），检索器自动降级为纯 BM25 模式。

  ---
  四、Phase 3：推理层（Reasoning Layer）

  推理层是系统的核心智能组件，实现基于 Actor-Critic 博弈框架的对抗辩论式漏洞分析。

  4.1 LLM 推理后端（llm_backend.py）

  4.1.1 GGUF 模型加载

  系统通过 llama-cpp-python 加载 GGUF 量化格式的 Qwen2.5-Coder-32B 模型。关键配置：

  LLMConfig(
      model_path="/path/to/qwen2.5-coder-32b.Q4_K_M.gguf",
      n_gpu_layers=-1,   # -1 = 全部层卸载到 GPU
      n_ctx=16384,        # 上下文窗口 16K tokens
      n_threads=4,        # CPU 线程数
      temperature=0.1,    # 低温度 = 更确定性的输出
      max_tokens=2

                                                                                                                                                                                                                                                                              
  ---
  1.4 依赖声明                                                                                                                                                                                                                                                              
   
  [project]                                                                                                                                                                                                                                                                 
  dependencies = [                                          
      "tree-sitter>=0.22,<0.26",        # Tree-sitter Python 绑定
      "tree-sitter-c>=0.21",            # C 语法预编译包
      "tree-sitter-cpp>=0.22",          # C++ 语法预编译包
      "pydantic>=2.0,<3.0",             # 数据模型与 JSON 序列化
      "rank-bm25>=0.2.2,<0.3",          # 纯 Python BM25 实现
      "numpy>=1.22",                    # 向量计算
      "sentence-transformers>=2.2.0,<4.0", # 嵌入模型加载
  ]

  [project.optional-dependencies]
  dev = ["pytest>=7.0"]
  gpu = ["llama-cpp-python>=0.2.0"]     # GGUF 推理（需 C++ 编译环境）

  所有核心依赖均以预编译 wheel 形式发布，可在离线环境通过 pip install --no-index --find-links=./wheels/ 安装。llama-cpp-python 作为可选依赖，需要 C++ 编译工具链；若需 CUDA 加速，必须以 CMAKE_ARGS="-DGGML_CUDA=on" pip install llama-cpp-python --force-reinstall
  --no-cache-dir 方式编译安装。

  ---
  二、Phase 1：解析层（Parsing Layer）

  解析层是整个系统的基座，负责将原始 C/C++ 源文件转化为结构化的中间表示。它基于 Tree-sitter 增量解析器实现，产出四类核心制品：AST 节点树、函数信息、控制流图（CFG）和代码分块（Chunk）。

  2.1 AST 解析器（ast_parser.py）

  2.1.1 设计原理

  Tree-sitter 是一个增量、容错的解析器生成框架。与 Clang AST 不同，Tree-sitter 直接在原始源文本上构建具体语法树（CST），不需要完整的编译环境（无需头文件、无需预处理器）。这使得它天然满足"物理行号保真"约束——每个 AST 节点的 start_point 和 end_point
  直接对应原始文件中的物理位置。

  2.1.2 行号转换机制

  Tree-sitter 返回的行号是 0-indexed 的 (row, column) 元组。系统在 _make_source_range() 函数中执行唯一一次 0→1 转换：

  def _make_source_range(node: Node) -> SourceRange:
      return SourceRange(
          start=SourceLocation(line=node.start_point[0] + 1, column=node.start_point[1]),
          end=SourceLocation(line=node.end_point[0] + 1, column=node.end_point[1]),
          start_byte=node.start_byte,
          end_byte=node.end_byte,
      )

  这是整个系统中行号从 0-indexed 转为 1-indexed 的唯一入口。此后所有下游模块（CFG、Slicer、Chunker、Retriever、Reasoning）使用的行号均为 1-indexed 物理行号，与编辑器中看到的行号完全一致。

  2.1.3 AST 节点转换

  _node_to_ast() 递归地将 Tree-sitter 的 Node 对象转换为系统内部的 ASTNode Pydantic 模型。转换过程中保留了 is_missing 标志，用于标记 Tree-sitter 在容错解析中插入的缺失节点：

  def _node_to_ast(node: Node, source: bytes, field_name=None) -> ASTNode:
      children = []
      for i, child in enumerate(node.children):
          child_field = node.field_name_for_child(i)
          children.append(_node_to_ast(child, source, child_field))
      return ASTNode(
          node_type=node.type,
          field_name=field_name,
          source_range=_make_source_range(node),
          text=source[node.start_byte:node.end_byte].decode("utf-8", errors="replace"),
          is_named=node.is_named,
          is_missing=node.is_missing,
          children=children,
      )

  2.1.4 函数提取

  extract_functions() 通过 BFS 遍历 AST 根节点，收集所有 function_definition 类型的节点。对每个函数提取：

  - 函数名：从 declarator 子节点递归查找最深层的 identifier
  - 返回类型：从 type 字段子节点提取
  - 参数列表：遍历 parameter_list 中的 parameter_declaration 节点，提取每个参数的名称和类型
  - 函数签名文本：从函数起始到函数体 { 之间的原始文本
  - 函数体范围：body 字段子节点（compound_statement）的行范围

  2.1.5 错误收集

  collect_errors() 遍历整棵 AST，收集所有 ERROR、MISSING 类型的节点以及 is_missing=True 的节点。每个错误记录其行范围和文本片段，存入 ParseResult.errors 列表。这些错误不会中断解析流程——这是容错性约束（Constraint A）的核心体现。

  2.1.6 语言自动检测

  系统通过文件扩展名自动检测语言：.c/.h → C，.cpp/.cc/.cxx/.hpp → C++。也可通过 CLI 参数 --language 手动指定。

  2.2 控制流图构建器（cfg_builder.py）

  2.2.1 设计原理

  CFG 是程序切片和数据流分析的基础。系统构建的是过程内（intra-procedural）CFG，即每个函数独立构建一张图。CFG 由基本块（BasicBlock）和有向边（CFGEdge）组成，每条边标注了控制流类型。

  2.2.2 构建算法

  _CFGBuilder 类通过递归下降遍历函数体 AST 来构建 CFG。核心方法 _process_statement() 根据 AST 节点类型分派到不同的处理器：

  简单语句（expression_statement、declaration）：追加到当前基本块，控制流直接穿过（fallthrough）。

  return 语句：追加到当前块，添加一条 RETURN 边到 EXIT 块，返回 None 表示后续不可达。

  if 语句：
  1. 将条件表达式追加到当前块
  2. 创建 then 块，添加 TRUE_BRANCH 边
  3. 如果有 else 分支，创建 else 块，添加 FALSE_BRANCH 边
  4. 创建 join 块，then/else 的出口都汇入 join
  5. 特别处理：Tree-sitter 将 else 分支包装在 else_clause 节点中，构建器会自动解包（unwrap）以获取内部的 if_statement 或 compound_statement

  while 语句：
  1. 创建条件块（循环头）、循环体块、join 块
  2. 条件块 → 循环体：TRUE_BRANCH
  3. 条件块 → join：FALSE_BRANCH
  4. 循环体出口 → 条件块：BACK_EDGE
  5. 将 join 压入 _break_targets 栈，条件块压入 _continue_targets 栈

  for 语句：
  1. 初始化器追加到当前块
  2. 创建条件块、循环体块、更新块、join 块
  3. 循环体出口 → 更新块 → 条件块（BACK_EDGE）
  4. continue 跳转到更新块（而非条件块）

  do-while 语句：
  1. 先创建循环体块，再创建条件块
  2. 条件块 → 循环体：TRUE_BRANCH（回边）
  3. 条件块 → join：FALSE_BRANCH

  switch 语句：
  1. 条件表达式追加到当前块
  2. 遍历 compound_statement 体中的 case_statement 子节点
  3. Tree-sitter C 语法中，default 也表示为 case_statement（无 value 字段），构建器通过检查 value 字段是否存在来区分 CASE 和 DEFAULT 边
  4. 相邻 case 之间如果没有 break，自动添加 fall-through 边

  goto/label 语句：
  1. goto 创建 GOTO 边到目标 label 块
  2. 如果 label 尚未出现（前向 goto），记入 _pending_gotos 列表
  3. labeled_statement 创建新块并注册到 _label_blocks 字典
  4. 后处理阶段解析所有 pending gotos

  break/continue：
  1. break 添加 BREAK 边到 _break_targets 栈顶
  2. continue 添加 CONTINUE 边到 _continue_targets 栈顶
  3. 如果栈为空（break/continue 出现在循环/switch 外），记录警告而非抛出异常

  2.2.3 容错性降级策略（Constraint A）

  _process_statement() 的最后一个分支是默认 fallback：

  # 任何未识别的节点类型（包括 ERROR、MISSING、preproc_ifdef 等）
  # 都被视为不透明的单行语句，追加到当前块并直接穿过
  self._append_stmt(current, node)
  if ntype in ("ERROR", "MISSING"):
      self.warnings.append(f"{ntype} node at line ... treated as opaque statement")
  return current  # fallthrough，绝不抛出异常

  这意味着即使源文件包含语法错误、未知宏、#ifdef 块，CFG 构建也不会崩溃。错误节点被当作普通语句处理，警告信息记录在 CFG.warnings 列表中。

  2.2.4 后处理

  构建完成后执行三步后处理：
  1. 解析前向 goto：遍历 _pending_gotos，将每个 goto 连接到对应的 label 块
  2. 计算块范围：根据每个块中语句的行范围计算块的 source_range
  3. 填充邻接表：根据边列表填充每个块的 predecessors 和 successors 列表

  2.3 程序切片器（slicer.py）

  2.3.1 设计原理

  程序切片是漏洞检测的核心技术之一。给定一个切片准则（某一行的某个变量），后向切片（backward slice）回答"哪些语句影响了这个变量在这一行的值？"，前向切片（forward slice）回答"这个变量在这一行的值会影响哪些后续语句？"

  系统实现的是基于工作列表（worklist）的过程内数据流切片算法。

  2.3.2 DEF/USE 分析（Constraint B：指针与结构体感知）

  C/C++ 的赋值远不止简单的 x = expr。切片器的 _extract_def_use() 函数处理以下所有形式：

  DEF 集合提取（_extract_def_targets）：
  - 简单标识符：x = ... → DEF = {"x"}
  - 指针解引用：*ptr = ... → DEF = {"*ptr", "ptr"}
  - 结构体字段：obj.field = ... → DEF = {"obj.field", "obj"}
  - 箭头访问：ptr->field = ... → DEF = {"ptr->field", "ptr"}
  - 数组下标：arr[i] = ... → DEF = {"arr[]", "arr"}，USE 额外包含 {"i"}
  - 嵌套访问：ptr->arr[i].x = ... → DEF = {"ptr->arr[].x", "ptr"}，USE 包含 {"i"}
  - 自增/自减：i++、--j → DEF = {"i"} / {"j"}

  USE 集合提取：
  - 赋值右侧的所有标识符
  - 条件表达式、函数参数、return 值中的标识符
  - 左值复合表达式中的基变量（如 arr[i] = x 中 i 是 USE）
  - 排除：函数调用中的被调用者名称、类型名称

  归一化路径表示：DEF/USE 集合中的元素使用归一化路径字符串：
  - "x" — 简单变量
  - "*ptr" — 解引用指针
  - "obj.field" — 结构体字段
  - "ptr->field" — 指针字段
  - "arr[]" — 数组访问（下标被擦除）

  前缀匹配规则：切片器在检查变量 v 是否在 DEF(s) 或 USE(s) 中时，使用前缀匹配："ptr" 匹配 "ptr"、"ptr->field"、"ptr->other"。这意味着对 ptr 的切片会包含所有触及 ptr 任何字段的语句——保守但对漏洞检测而言是安全的。

  ERROR 节点处理（Constraint A）：对于 ERROR 或 MISSING 类型的语句，_extract_def_use() 返回空集 (∅, ∅)。这些节点对切片透明——它们既不定义也不使用任何变量，除非它们恰好在切片准则行上。

  2.3.3 后向切片算法

  输入: CFG, 切片准则 (line, variable)
  输出: 包含在切片中的语句集合

  1. 定位准则语句在 CFG 中的位置 (block_id, stmt_index)
  2. 初始化工作列表: [(block_id, stmt_index, variable, is_seed=True)]
  3. while 工作列表非空:
     a. 取出 (bid, sidx, var, is_seed)
     b. 在当前块中从 sidx 向前搜索（is_seed 时从 sidx-1 开始，否则从 sidx 开始）
     c. 找到 DEF(var) 的语句 → 加入切片，将其 USE 集合中的变量加入工作列表
     d. 未找到 → 递归遍历前驱块（穿越空块直到找到有语句的块）

  关键实现细节：
  - is_seed 标志区分初始准则语句和从前驱块进入的语句，避免跳过前驱块的最后一条语句
  - _propagate_to_predecessors() 递归穿越空的 join 块，确保切片能穿越 if/else 分支的汇合点

  2.3.4 前向切片算法

  与后向切片对称：从准则语句出发，沿 CFG 正向搜索，跟踪 DEF→USE 链。当变量被重新定义（killed）时停止在该路径上的传播。

  2.4 代码分块器（chunker.py）

  2.4.1 设计原理

  分块器将解析后的函数切分为适合 RAG 检索的代码片段（Chunk）。每个 Chunk 携带完整的元数据（文件路径、函数名、行范围、AST 节点类型），供检索层进行精确的元数据过滤。

  2.4.2 两级分块策略

  第一级：函数级分块。 每个函数整体作为一个 FUNCTION 类型的 Chunk。这是始终产出的基础分块。

  第二级：语义块分块。 对于超过 split_threshold（默认 30 行）的长函数，进一步拆分为 BLOCK 类型的 Chunk：
  - 每个复合控制流语句（if、for、while、do、switch）独立成块
  - 连续的简单语句（声明、表达式语句）按最大 max_simple_group（默认 15 行）分组
  - 每个语义块的 metadata["context"] 字段存储父函数的签名文本，为检索提供上下文

  2.4.3 Chunk 数据模型

  class Chunk(BaseModel):
      chunk_id: str          # 格式: "{file_path}:{function_name}:{start_line}-{end_line}"
      kind: ChunkKind        # FUNCTION | BLOCK | SLICE
      file_path: str
      function_name: str | None
      source_range: SourceRange
      text: str              # 原始源代码文本
      line_count: int
      ast_node_types: list[str]  # 该 Chunk 中出现的所有 AST 节点类型（排序后）
      metadata: dict[str, str]   # 可选元数据: "has_errors", "context"

  ast_node_types 字段特别重要——它允许检索层按 AST 特征过滤。例如，只检索包含 call_expression 的 Chunk（即包含函数调用的代码块），或只检索包含 goto_statement 的 Chunk。

  2.4.4 宏调用处理（Constraint C）

  系统严格执行"所见即所得"原则。Tree-sitter 是具体语法树（CST）解析器，宏调用（如 SAFE_FREE(buf)）在语法层面被解析为普通的 call_expression，与 free(buf) 没有区别。分块器不做任何特殊处理——宏调用的原始文本和行号被原样保留在 Chunk 中。

  ---
  三、Phase 2：检索层（Retrieval Layer）

  检索层实现 BM25（稀疏）与 Embedding（稠密）异构双路检索，通过 RRF（Reciprocal Rank Fusion）算法融合两路结果。它消费 Phase 1 产出的 Chunk 对象，为 Phase 3 的推理层提供相似代码模式上下文。

  3.1 C/C++ 感知分词器（tokenizer.py）

  3.1.1 设计原理

  通用的 NLP 分词器（如 NLTK、spaCy）不理解 C/C++ 的词法结构。ptr->field 会被错误地拆分，camelCase 标识符不会被分解，运算符 ==、!= 会被丢弃。系统实现了专门的 C/C++ 感知分词器。

  3.1.2 分词流水线

  tokenize_code(text) 的处理步骤：

  1. 剥离注释和字符串字面量：用正则表达式匹配 //、/* */、"..."、'...'，替换为空格。这避免了注释内容和字符串常量干扰检索。
  2. 保护多字符运算符：将 -> 替换为占位符 _OP_ARROW_，:: 替换为 _OP_SCOPE_，以此类推。共处理 22 种运算符，按长度降序替换以避免 <<= 被 << 和 = 分别匹配。
  3. 按非字母数字边界拆分：re.split(r'[^a-zA-Z0-9_]+', text)
  4. camelCase 和 snake_case 子拆分：maxBufferSize → ["maxbuffersize", "max", "buffer", "size"]。保留原始复合 token 以支持精确匹配，同时拆分子词以支持模糊匹配。
  5. 小写化
  6. 还原运算符占位符：_OP_ARROW_ → op_arrow
  7. 过滤单字符 token：除 C 关键字 if、do 外，单字符 token 被过滤（它们通常是变量名 i、j，信息量低）。
  8. 保留危险 API 名称：malloc、free、strcpy、sprintf、gets、system 等 60+ 个危险函数名被保留为关键 token，因为它们是漏洞检测的强信号。

  tokenize_query(query) 使用相同流水线，但跳过注释/字符串剥离步骤（查询文本通常很短，不包含注释）。

  3.2 BM25 稀疏索引（bm25_index.py）

  3.2.1 设计原理

  BM25（Best Matching 25）是经典的基于词频的稀疏检索算法。它不需要任何训练或模型文件，纯 Python 实现，完全离线友好。对于代码检索，BM25 擅长精确的词法匹配——当查询包含特定函数名（如 strcpy）或变量名时，BM25 能精准命中包含该词的代码块。

  系统使用 rank_bm25.BM25Okapi 实现，这是 BM25 的 Okapi 变体，考虑了文档长度归一化。

  3.2.2 索引构建

  def build(self, chunks: list[Chunk]) -> None:
      self._chunk_ids = [c.chunk_id for c in chunks]
      self._chunks = {c.chunk_id: c for c in chunks}
      self._tokenized_corpus = [tokenize_code(c.text) for c in chunks]
      self._bm25 = BM25Okapi(self._tokenized_corpus)

  3.2.3 查询与过滤

  查询时，BM25 对所有文档计算分数，然后通过元数据过滤掩码（mask）将不符合条件的文档分数置零：

  scores = self._bm25.get_scores(query_tokens)
  if filters:
      mask = self._build_filter_mask(filters)  # 不符合条件的位置为 0.0
      scores = scores * mask
  top_indices = np.argsort(scores)[::-1][:top_k]

  支持的过滤维度：file_paths、function_names、kinds（FUNCTION/BLOCK/SLICE）、ast_node_types（要求 Chunk 包含所有指定的 AST 节点类型）。

  3.2.4 持久化

  BM25 索引通过 pickle 序列化到磁盘，存储内容包括：chunk_ids 列表、chunks 字典（JSON 格式）、分词后的语料库。加载时重建 BM25Okapi 对象。

  3.3 稠密向量索引（embedding_index.py）

  3.3.1 设计原理

  稠密检索通过将代码片段编码为高维向量，在语义空间中计算相似度。它弥补了 BM25 的不足——当查询使用自然语言描述（如"缓冲区溢出"）而代码中没有这些词时，稠密检索仍能通过语义相似性找到相关代码。

  系统使用 SentenceTransformer 加载本地嵌入模型（CodeFuse-CGE），通过纯 NumPy 实现向量存储和余弦相似度计算，避免了 ChromaDB 等向量数据库的 C++ 编译依赖。

  3.3.2 离线安全约束

  Constraint D — 遥测关闭：虽然最终未使用 ChromaDB，但代码中仍保留了遥测关闭的模式，作为未来切换到 ChromaDB 时的参考。

  Constraint E — 严格离线加载：

  def _ensure_model(self):
      os.environ["HF_HUB_OFFLINE"] = "1"        # 阻止 HuggingFace Hub 访问
      os.environ["TRANSFORMERS_OFFLINE"] = "1"   # 阻止 Transformers 库联网
      if not self._config.model_path:
          raise ValueError("config.model_path is required for offline deployment.")
      self._model = SentenceTransformer(
          self._config.model_path,
          device=device,
          trust_remote_code=False,    # 禁止执行不受信任的模型代码
          local_files_only=True,      # 仅从本地路径加载
      )

  三重防护：环境变量 + local_files_only 参数 + model_path 非空校验。即使代码中意外写入了模型名称而非路径，也不会触发网络请求。

  Constraint F — 动态设备选择：

  def _resolve_device(device_cfg: str) -> str:
      if device_cfg == "auto":
          import torch
          return "cuda" if torch.cuda.is_available() else "cpu"
      return device_cfg

  当 device="auto" 时自动检测 GPU 可用性。宿主机若配备 24GB GPU，索引构建时的批量编码将自动使用 GPU 加速。

  3.3.3 向量存储与检索

  索引构建时，将所有 Chunk 文本批量编码为归一化向量，存储在 NumPy 数组中：

  embeddings = model.encode(texts, normalize_embeddings=True)
  self._embeddings = np.vstack(all_embeddings)

  查询时，计算查询向量与所有文档向量的余弦相似度（由于向量已归一化，余弦相似度等价于点积）：

  query_vec = model.encode([query_text], normalize_embeddings=True).flatten()
  scores = self._embeddings @ query_vec  # 矩阵-向量乘法

  3.4 RRF 融合算法（fusion.py）

  3.4.1 算法原理

  Reciprocal Rank Fusion（RRF）是一种无需训练的排名融合算法。它的核心思想是：一个文档在多个排名列表中排名越靠前，其融合分数越高。

  公式：score(d) = Σ weight_i / (k + rank_i(d))

  其中 k 是平滑常数（默认 60），rank_i(d) 是文档 d 在第 i 个排名列表中的排名。

  3.4.2 实现

  def reciprocal_rank_fusion(bm25_results, embedding_results, top_k=20, rrf_k=60,
                             bm25_weight=1.0, embedding_weight=1.0):
      scores = {}
      for r in bm25_results:
          scores[r.chunk_id] = scores.get(r.chunk_id, 0) + bm25_weight / (rrf_k + r.rank)
      for r in embedding_results:
          scores[r.chunk_id] = scores.get(r.chunk_id, 0) + embedding_weight / (rrf_k + r.rank)
      sorted_ids = sorted(scores.keys(), key=lambda cid: scores[cid], reverse=True)
      return sorted_ids[:top_k]  # 返回融合后的 top-k 结果

  关键特性：
  - 只出现在一个列表中的文档仍然获得分数（另一项

  ● 接着函数提取部分继续。                                                                                                                                                                                                                                                    
                                                                                                                                                                                                                                                                          
  ---                                                                                                                                                                                                                                                                       
  2.1.4 函数提取
                                                                                                                                                                                                                                                                            
  extract_functions() 通过广度优先遍历 AST 根节点，收集所有 function_definition 类型的节点。对每个函数节点，提取以下信息：

  - 函数名：通过 _find_deepest_identifier() 递归查找 declarator 字段中最深层的 identifier 节点，处理指针声明符（如 int *foo()）和嵌套声明符的情况。
  - 返回类型：从 type 字段提取原始文本。
  - 参数列表：遍历 parameter_list 中的 parameter_declaration 节点，分别提取类型文本和参数名。
  - 函数体范围：记录 body（compound_statement）的 SourceRange，用于后续 CFG 构建。
  - 签名文本：从函数起始字节到函数体起始字节之间的原始文本，保留原始格式。

  2.1.5 错误收集

  collect_errors() 遍历整棵 AST，收集所有 ERROR 类型节点和 is_missing=True 的节点。每个错误记录包含节点类型、行号范围和前 80 个字符的文本预览。这些错误信息被写入 ParseResult.errors，供下游模块参考但不阻断处理流程。

  2.1.6 语言自动检测

  detect_language() 根据文件扩展名自动判断语言类型：

  ┌─────────────────────────────────┬──────┐
  │             扩展名              │ 语言 │
  ├─────────────────────────────────┼──────┤
  │ .c, .h                          │ C    │
  ├─────────────────────────────────┼──────┤
  │ .cpp, .cc, .cxx, .hpp, .hxx, .C │ C++  │
  └─────────────────────────────────┴──────┘

  2.2 控制流图构建器（cfg_builder.py）

  2.2.1 设计原理

  CFG 构建器在单个函数的 AST 上执行递归下降遍历，将函数体转化为由基本块（BasicBlock）和有向边（CFGEdge）组成的控制流图。每个基本块包含一组顺序执行的语句（ASTNode 列表），边携带类型标签（条件分支、循环回边、goto 跳转等）。

  CFG 的核心不变量：
  - 每个 CFG 恰好有一个 Entry 块和一个 Exit 块
  - Entry 块无前驱，Exit 块无后继
  - 所有正常终止的执行路径最终到达 Exit 块
  - 每条边携带 CFGEdgeKind 枚举标签

  2.2.2 边类型枚举

  UNCONDITIONAL  — 无条件顺序流转
  TRUE_BRANCH    — if/while/for/do 条件为真
  FALSE_BRANCH   — if/while/for/do 条件为假
  CASE           — switch 的 case 分支
  DEFAULT        — switch 的 default 分支
  BACK_EDGE      — 循环回边（for/while 的 update→condition）
  BREAK          — break 跳转到循环/switch 出口
  CONTINUE       — continue 跳转到循环头部
  GOTO           — goto 跳转到标签
  RETURN         — return 跳转到 Exit 块

  2.2.3 语句分派逻辑

  _process_statement() 是 CFG 构建的核心分派函数。它根据 AST 节点类型选择不同的处理策略：

  简单语句（expression_statement、declaration）：追加到当前基本块，顺序流转。

  return 语句：追加到当前块，添加 RETURN 边到 Exit 块，返回 None（表示此路径已终止）。

  if 语句：
  1. 将条件表达式追加到当前块
  2. 创建 then 块，添加 TRUE_BRANCH 边
  3. 处理 consequence（then 分支）
  4. 如果存在 alternative（else 分支），需要特别处理 Tree-sitter 的 else_clause 包装节点——先解包 else_clause，再判断内部是 if_statement（else-if 链）还是 compound_statement（else 块）
  5. 创建 join 块，所有分支汇合

  while 语句：
  1. 创建 condition 块、body 块、join 块
  2. 当前块 → condition 块（UNCONDITIONAL）
  3. condition 块 → body 块（TRUE_BRANCH）、join 块（FALSE_BRANCH）
  4. body 块末尾 → condition 块（BACK_EDGE）
  5. 将 join 块压入 _break_targets 栈，condition 块压入 _continue_targets 栈

  for 语句：
  1. initializer 追加到当前块
  2. 创建 condition 块、body 块、update 块、join 块
  3. body 末尾 → update 块 → condition 块（BACK_EDGE）
  4. continue 目标指向 update 块（而非 condition 块）

  do-while 语句：
  1. 先创建 body 块，再创建 condition 块
  2. body 末尾 → condition 块
  3. condition 块 → body 块（TRUE_BRANCH，即循环回边）、join 块（FALSE_BRANCH）

  switch 语句：
  1. 条件追加到当前块
  2. 遍历 compound_statement 体中的 case_statement 节点
  3. Tree-sitter C 语法中，default 也表示为 case_statement（无 value 字段），通过检查 value 字段是否存在来区分 CASE 和 DEFAULT
  4. 处理 fall-through：前一个 case 的末尾如果没有 break/return，则添加 UNCONDITIONAL 边到下一个 case

  goto 语句：
  1. 提取目标标签名（statement_identifier 或 identifier 节点）
  2. 如果标签已注册（前向引用已解析），立即添加 GOTO 边
  3. 否则加入 _pending_gotos 列表，在后处理阶段解析

  labeled 语句：
  1. 注册标签名到 _label_blocks 字典
  2. 创建新基本块作为标签目标
  3. 递归处理标签内的语句

  2.2.4 容错性策略（Constraint A）

  _process_statement() 的最后一个分支是默认 fallback：

  # 任何未识别的节点类型（包括 ERROR、MISSING、preproc_ifdef 等）
  # 都被视为不透明的单行语句，追加到当前块并顺序流转
  self._append_stmt(current, node)
  if ntype in ("ERROR", "MISSING"):
      self.warnings.append(f"{ntype} node at line ... treated as opaque statement")
  return current  # 顺序流转，不抛异常

  这确保了即使源文件包含语法错误、缺失的头文件、复杂的嵌套宏或 #ifdef 块，CFG 构建也不会崩溃。错误节点被当作普通语句处理，警告信息记录在 CFG.warnings 中。

  2.2.5 后处理

  CFG 构建完成后执行三个后处理步骤：
  1. 解析前向 goto：遍历 _pending_gotos，将每个待解析的 goto 与已注册的标签块关联
  2. 计算块范围：根据每个块中语句的 SourceRange 计算块级别的 SourceRange
  3. 填充邻接表：根据边列表填充每个块的 predecessors 和 successors 列表

  2.3 程序切片器（slicer.py）

  2.3.1 设计原理

  程序切片是一种经典的程序分析技术，给定一个切片准则（某行代码中的某个变量），提取所有影响该变量值的语句（后向切片）或受该变量影响的语句（前向切片）。在漏洞检测场景中，切片用于追踪数据从 Source（如用户输入）到 Sink（如危险 API 调用）的传播路径。

  系统实现的是过程内（intra-procedural）数据流切片，基于 CFG 上的 DEF/USE 链分析。

  2.3.2 指针与结构体感知的 DEF/USE 分析（Constraint B）

  C/C++ 的赋值远不止简单的标识符。_extract_def_use() 函数处理以下复杂左值模式：

  ┌──────────────────────┬─────────────────────────┬───────────────────────────┐
  │       代码模式       │        DEF 集合         │         USE 集合          │
  ├──────────────────────┼─────────────────────────┼───────────────────────────┤
  │ x = expr             │ {"x"}                   │ expr 中的标识符           │
  ├──────────────────────┼─────────────────────────┼───────────────────────────┤
  │ *ptr = expr          │ {"*ptr", "ptr"}         │ {"ptr"} + expr 中的标识符 │
  ├──────────────────────┼─────────────────────────┼───────────────────────────┤
  │ obj.field = expr     │ {"obj.field", "obj"}    │ expr 中的标识符           │
  ├──────────────────────┼─────────────────────────┼───────────────────────────┤
  │ ptr->field = expr    │ {"ptr->field", "ptr"}   │ expr 中的标识符           │
  ├──────────────────────┼─────────────────────────┼───────────────────────────┤
  │ arr[i] = expr        │ {"arr[]", "arr"}        │ {"i"} + expr 中的标识符   │
  ├──────────────────────┼─────────────────────────┼───────────────────────────┤
  │ ptr->arr[i].x = expr │ {"ptr->arr[].x", "ptr"} │ {"i"} + expr 中的标识符   │
  ├──────────────────────┼─────────────────────────┼───────────────────────────┤
  │ i++ / --j            │ {"i"} / {"j"}           │ {"i"} / {"j"}             │
  └──────────────────────┴─────────────────────────┴───────────────────────────┘

  DEF/USE 集合中的元素使用归一化路径表示法：
  - "x" — 简单变量
  - "*ptr" — 解引用指针
  - "obj.field" — 结构体字段
  - "ptr->field" — 指针字段
  - "arr[]" — 数组访问（下标被擦除，因为不追踪具体值）

  _normalize_access_path() 函数递归遍历左值 AST 节点，构建归一化路径并收集下标中使用的索引变量。

  2.3.3 前缀匹配规则

  切片器在检查变量是否匹配时使用前缀匹配：切片准则 "ptr" 会匹配 "ptr"、"ptr->field"、"ptr->other" 等所有以 ptr 为根的访问路径。这是保守但安全的策略——对于漏洞检测，宁可多包含一些语句（假阳性），也不能遗漏关键的数据流传播步骤。

  2.3.4 后向切片算法

  后向切片从切片准则出发，沿 CFG 反向追踪变量的定义链：

  输入: CFG, 切片准则 (line, variable)
  输出: 包含在切片中的语句集合

  1. 定位切片准则所在的基本块和语句索引
  2. 初始化工作列表: [(block_id, stmt_idx, variable, is_seed=True)]
  3. while 工作列表非空:
     a. 取出 (bid, sidx, var, is_seed)
     b. 从 sidx-1（如果 is_seed）或 sidx（如果非 seed）开始向上扫描当前块
     c. 如果找到 DEF(var) 的语句:
        - 将该语句加入切片
        - 将该语句的 USE 集合中的每个变量加入工作列表
        - 标记 found=True, break
     d. 如果未找到（到达块头部）:
        - 递归遍历前驱块（穿越空块直到找到有语句的块）
        - 将前驱块的最后一条语句加入工作列表，is_seed=False

  关键实现细节：is_seed 标志区分了初始切片准则（跳过自身）和从前驱块传播过来的搜索（需要检查入口语句）。_propagate_to_predecessors() 递归穿越空的 join 块，确保切片能正确穿越 if/else 分支的汇合点。

  2.3.5 前向切片算法

  前向切片是后向切片的对称操作，沿 CFG 正向追踪变量的使用链：

  1. 从切片准则向下扫描当前块
  2. 如果找到 USE(var) 的语句，加入切片，将其 DEF 集合加入工作列表
  3. 如果找到 DEF(var) 的语句（变量被重新定义），停止在当前块的搜索
  4. 到达块末尾时，递归遍历后继块（穿越空块）

  2.3.6 ERROR 节点处理

  对于 ERROR 和 MISSING 类型的 AST 节点，_extract_def_use() 返回空的 DEF 和 USE 集合。这意味着错误节点对切片是"透明"的——它们既不定义也不使用任何变量，不会被包含在切片中（除非它们恰好位于切片准则行上）。这是保守但安全的策略。

  2.4 代码分块器（chunker.py）

  2.4.1 设计原理

  分块器将解析后的函数切分为适合 RAG 检索的代码片段（Chunk）。每个 Chunk 携带完整的元数据（文件路径、函数名、行号范围、AST 节点类型集合），使得检索层可以基于元数据进行精确过滤。

  2.4.2 两级分块策略

  第一级：函数级分块。 每个函数整体作为一个 Chunk，类型为 FUNCTION。这是始终产生的基础分块。

  第二级：语义块分块。 对于超过 split_threshold（默认 30 行）的长函数，进一步按语义结构切分：
  - 每个复合控制流语句（if_statement、for_statement、while_statement、do_statement、switch_statement）独立成块，类型为 BLOCK
  - 连续的简单语句（声明、表达式语句）按最大行数（默认 15 行）分组
  - 每个语义块的 metadata["context"] 字段记录父函数的签名文本，为检索提供上下文

  2.4.3 Chunk 数据模型

  class Chunk(BaseModel):
      chunk_id: str          # 格式: "{file_path}:{function_name}:{start_line}-{end_line}"
      kind: ChunkKind        # FUNCTION | BLOCK | SLICE
      file_path: str
      function_name: str | None
      source_range: SourceRange
      text: str              # 原始源代码文本
      line_count: int
      ast_node_types: list[str]  # 该 Chunk 中出现的所有 AST 节点类型（排序后）
      metadata: dict[str, str]   # 可选元数据（has_errors, context 等）

  ast_node_types 字段特别重要——它允许检索层按 AST 结构过滤。例如，只检索包含 call_expression 的 Chunk（即包含函数调用的代码块），或只检索包含 goto_statement 的 Chunk。

  2.4.4 宏调用处理（Constraint C）

  分块器严格执行"所见即所得"原则。大写的宏函数调用（如 SAFE_FREE(buf)、MEMSET(buf, 0, size)）在 Tree-sitter 中被解析为普通的 call_expression，分块器不做任何特殊处理。这些宏调用的原始文本和行号被完整保留在 Chunk 中。

  2.5 解析层 CLI

  # 基本解析（JSON 输出）
  python -m mmrag.parsing tests/fixtures/sample.c

  # 文本摘要输出
  python -m mmrag.parsing tests/fixtures/sample.c --output text

  # 后向切片
  python -m mmrag.parsing tests/fixtures/sample.c --slice 28:result --direction backward

  # 指定语言
  python -m mmrag.parsing tests/fixtures/sample.c --language c

  ---
  三、Phase 2：检索层（Retrieval Layer）

  检索层实现 BM25（稀疏）与 Embedding（稠密）异构双路检索，通过 RRF（Reciprocal Rank Fusion）算法融合两路结果。它消费 Phase 1 产出的 Chunk 对象，为 Phase 3 的推理层提供相似代码模式上下文。

  3.1 C/C++ 感知分词器（tokenizer.py）

  3.1.1 设计原理

  通用的 BM25 分词器（按空格和标点分割）对代码效果很差，因为代码中的标识符命名约定（camelCase、snake_case）和运算符（->、::）携带重要的语义信息。系统实现了专门的 C/C++ 感知分词器。

  3.1.2 分词流水线

  tokenize_code(text) 的处理流程：

  原始代码文本
      │
      ▼
  ① 剥离注释和字符串字面量
     //... 和 /* ... */ 替换为空格
     "..." 和 '...' 替换为空格
      │
      ▼
  ② 保护多字符运算符
     -> 替换为 _OP_ARROW_ 占位符
     :: 替换为 _OP_SCOPE_ 占位符
     ==, !=, <=, >=, &&, ||, ++, -- 等同理
     （按长度降序替换，避免 <<= 被 << 先匹配）
      │
      ▼
  ③ 按非字母数字字符分割
     re.split(r'[^a-zA-Z0-9_]+', text)
      │
      ▼
  ④ 标识符子分割
     camelCase: maxBufferSize → ["maxbuffersize", "max", "buffer", "size"]
     snake_case: max_buffer_size → ["max_buffer_size", "max", "buffer", "size"]
     保留原始复合词（小写化）作为第一个 token
      │
      ▼
  ⑤ 还原运算符占位符
     _OP_ARROW_ → "op_arrow"
     _OP_SCOPE_ → "op_scope"
      │
      ▼
  ⑥ 过滤单字符 token
     除 C 关键字（"if", "do"）外，移除所有单字符 token
      │
      ▼
  最终 token 列表

  3.1.3 关键词保留

  分词器维护一个包含 80+ 个条目的关键词集合，涵盖：
  - C/C++ 语言关键字（if, for, while, struct, class 等）
  - 危险 API 函数名（malloc, free, strcpy, sprintf, gets, system 等）
  - 常量（NULL, true, false）

  这些关键词在分词后被保留，确保 BM25 能够基于危险 API 名称进行精确匹配。

  3.2 BM25 稀疏索引（bm25_index.py）

  3.2.1 索引构建

  BM25Index.build(chunks) 使用 rank_bm25.BM25Okapi 算法在分词后的 Chunk 文本语料上构建倒排索引。BM25Okapi 是 BM25 的标准变体，考虑了词频（TF）、逆文档频率（IDF）和文档长度归一化。

  3.2.2 查询与过滤

  查询流程：
  1. 对查询文本执行 tokenize_query()（与 tokenize_code 相同流水线，但跳过注释/字符串剥离）
  2. 调用 BM25Okapi.get_scores() 获取所有 Chunk 的 BM25 分数
  3. 如果指定了 MetadataFilter，构建过滤掩码（NumPy 数组），将不满足条件的 Chunk 分数置零
  4. 对分数数组执行 argsort 取 top-k

  元数据过滤支持四个维度：
  - file_paths: 限定文件路径
  - function_names: 限定函数名
  - kinds: 限定 Chunk 类型（function/block/slice）
  - ast_node_types: 要求 Chunk 包含指定的 AST 节点类型（AND 语义）

  3.2.3 持久化

  索引通过 Python pickle 序列化到磁盘，存储内容包括：chunk_ids 列表、chunks 字典（Pydantic model_dump）、分词后的语料。加载时重建 BM25Okapi 对象。

  3.3 稠密向量索引（embedding_index.py）

  3.3.1 设计原理

  稠密检索使用预训练的代码嵌入模型将 Chunk 文本编码为高维向量，通过余弦相似度进行语义匹配。与 BM25 的词汇匹配不同，稠密检索能捕捉语义相似性（例如，malloc 和 calloc 在向量空间中距离较近）。

  系统使用纯 NumPy 实现向量存储和检索（替代 ChromaDB），避免了 hnswlib C++ 编译依赖的问题，同时保持了完全离线的能力。

  3.3.2 离线安全约束

  Constraint D — 遥测关闭： 在任何 chromadb 相关导入之前设置 os.environ["ANONYMIZED_TELEMETRY"] = "False"。（注：当前实现已替换为纯 NumPy，但环境变量设置保留作为防御性措施。）

  Constraint E — 严格离线加载：
  os.environ["HF_HUB_OFFLINE"] = "1"
  os.environ["TRANSFORMERS_OFFLINE"] = "1"
  self._model = SentenceTransformer(
      config.model_path,       # 必须是本地绝对路径
      device=device,
      trust_remote_code=False,
      local_files_only=True,
  )
  如果 model_path 为空，直接抛出 ValueError，绝不尝试从 HuggingFace Hub 下载。

  Constraint F — 动态设备分配：
  def _resolve_device(device_cfg: str) -> str:
      if device_cfg == "auto":
          import torch
          return "cuda" if torch.cuda.is_available() else "cpu"
      return device_cfg
  宿主机配备 GPU 时自动使用 CUDA 加速嵌入计算，大幅提升 build() 阶段的索引速度。

  3.3.3 索引构建与查询

  构建：按 embedding_batch_size（默认 64）分批编码 Chunk 文本，L2 归一化后存储为 NumPy 矩阵。

  查询：编码查询文本 → 与索引矩阵做矩阵乘法（因已归一化，等价于余弦相似度）→ 应用元数据过滤掩码 → argsort 取 top-k。

  3.4 RRF 融合算法（fusion.py）

  3.4.1 算法原理

  Reciprocal Rank Fusion（RRF）是一种无需训练的排名融合算法，通过倒数排名加权合并多路检索结果：

  score(d) = Σ weight_i / (k + rank_i(d))

  其中 k 是平滑常数（默认 60），rank_i(d) 是文档 d 在第 i 路检索中的排名，weight_i 是该路的权重。

  3.4.2 实现细节

  def reciprocal_rank_fusion(
      bm25_results, embedding_results,
      top_k=20, rrf_k=60,
      bm25_weight=1.0, embedding_weight=1.0,
  ) -> list[RetrievalResult]:
      scores = {}
      for r in bm25_results:
          scores[r.chunk_id] += bm25_weight / (rrf_k + r.rank)
      for r in embedding_results:
          scores[r.chunk_id] += embedding_weight / (rrf_k + r.rank)
      # 按融合分数降序排列，取 top_k

  RRF 的优势：
  - 只出现在一路结果中的 Chunk 仍然可以进入最终排名（另一路贡献为 0）
  - 通过调整 bm25_weight 和 embedding_weight 可以控制两路的相对重要性
  - rrf_k=60 是文献中的标准值，使得排名靠前的结果获得显著更高的权重

  3.5 统一检索器（retriever.py）

  Retriever 类编排整个检索流程：

  class Retriever:
      def index(self, chunks) -> IndexStats          # 构建双路索引
      def query(self, query_text, top_k, filters)    # 双路检索 + RRF 融合
      def query_bm25_only(...)                       # 仅 BM25
      def query_embedding_only(...)                  # 仅嵌入
      def save(self) / load(cls, config)             # 持久化
      def stats(self) -> IndexStats                  # 索引统计

  query() 的内部流程：
  1. 计算 fetch_k = top_k × multiplier（默认 3 倍，确保融合前有足够候选）
  2. 并行执行 BM25 查询和 Embedding 查询
  3. 如果两路都有结果，执行 RRF 融合
  4. 如果只有一路有结果（例如未配置嵌入模型），直接返回该路结果

  3.6 检索层 CLI

  # 索引文件
  python -m mmrag.retrieval index tests/fixtures/sample.c --bm25-path ./index.pkl

  # BM25 查询
  python -m mmrag.retrieval query "malloc free buffer overflow" --mode bm25 --bm25-path ./index.pkl

  # 带过滤的查询
  python -m mmrag.retrieval query "strcpy" --filter-func resource_handler --mode bm25

  # 查看索引统计
  python -m mmrag.retrieval stats --bm25-path ./index.pkl

  ---
  四、Phase 3：推理层（Reasoning Layer）

  推理层是系统的核心智能组件，实现了基于 Actor-Critic 博弈框架的对抗辩论机制。三个 LLM 智能体（Attacker、Defender、Judge）围绕代码片段展开两轮结构化辩论，最终产出带有完整证据链的漏洞报告。

  4.1 LLM 推理后端（llm_backend.py）

  4.1.1 GGUF 模型加载

  系统使用 llama-cpp-python 作为推理后端，直接加载 GGUF 量化格式的模型文件。模型采用懒加载模式——首次调用 generate() 时才实际加载模型到内存。

  class LLMBackend:
      def _ensure_model(self):
          from llama_cpp import Llama
          effective_layers = _resolve_gpu_layers(self._config)
          self._model = Llama(
              model_path=self._config.model_path,
              n_gpu_layers=effective_layers,
              n_ctx=self._config.n_ctx,      # 默认 16384
              n_threads=self._config.n_threads,
              seed=self._config.seed,
              verbose=False,
          )

  `n_ctx=

   接着 while 语句处理继续。                                                                                                                                                                                                                                                 
                                                                                                                                                                                                                                                                          
  ---                                                                                                                                                                                                                                                                       
  while 语句：
  1. 创建 condition 块、body 块、join 块                                                                                                                                                                                                                                    
  2. 当前块 → condition 块（UNCONDITIONAL）                 
  3. condition 块 → body 块（TRUE_BRANCH）
  4. condition 块 → join 块（FALSE_BRANCH）
  5. 将 join 压入 _break_targets 栈，condition 压入 _continue_targets 栈
  6. 处理循环体
  7. body 出口 → condition 块（BACK_EDGE）
  8. 弹出 break/continue 栈

  for 语句：
  1. 将 initializer 追加到当前块
  2. 创建 condition 块、body 块、update 块、join 块
  3. 当前块 → condition（UNCONDITIONAL）
  4. condition → body（TRUE_BRANCH），condition → join（FALSE_BRANCH）
  5. body 出口 → update（UNCONDITIONAL）
  6. update → condition（BACK_EDGE）
  7. continue 目标指向 update 块（而非 condition），确保循环变量更新不被跳过

  do-while 语句：
  1. 创建 body 块、condition 块、join 块
  2. 当前块 → body（UNCONDITIONAL）——先执行循环体
  3. body 出口 → condition（UNCONDITIONAL）
  4. condition → body（TRUE_BRANCH）——回到循环体
  5. condition → join（FALSE_BRANCH）——退出循环

  switch 语句：
  1. 将条件表达式追加到当前块
  2. 创建 join 块，压入 _break_targets 栈
  3. 遍历 switch body 中的 case_statement 节点。Tree-sitter C 语法中，case 和 default 都表示为 case_statement 节点——通过检查是否存在 value 字段来区分：有 value 的是 case，无 value 的是 default
  4. 为每个 case 创建独立块，添加 CASE 或 DEFAULT 边
  5. 处理 fall-through：如果前一个 case 没有 break/return 终止，添加 UNCONDITIONAL 边到下一个 case 块
  6. 如果没有 default 分支，添加 UNCONDITIONAL 边从 switch 头到 join 块

  goto 语句：
  1. 追加到当前块
  2. 提取目标标签名（statement_identifier 或 identifier 节点）
  3. 如果标签已在 _label_blocks 中注册（前向引用已解析），立即添加 GOTO 边
  4. 否则加入 _pending_gotos 列表，等待后处理阶段解析

  labeled 语句：
  1. 提取标签名
  2. 创建新的基本块，注册到 _label_blocks
  3. 当前块 → 标签块（UNCONDITIONAL）
  4. 递归处理标签后的内部语句

  2.2.4 容错性策略（Constraint A）

  _process_statement() 的最后是一个 default fallback 分支。任何不在已知分派表中的节点类型——包括 ERROR、MISSING、preproc_ifdef、preproc_def 以及任何未来可能出现的未知类型——都被当作不透明的单行语句处理：追加到当前基本块，无条件流转到下一条语句。同时向 CFG.warnings
  列表记录一条警告信息。

  这意味着：即使源文件中有语法错误、缺失的头文件导致的未知宏、或者 #ifdef 条件编译块出现在函数体内部，CFG 构建器也不会抛出异常。它会将这些无法理解的节点视为"黑盒语句"，保守地假设它们顺序执行。

  2.2.5 后处理

  CFG 构建完成后执行三个后处理步骤：

  1. 解析前向 goto：遍历 _pending_gotos，将每个待解析的 goto 与 _label_blocks 中的目标块关联。未解析的标签记录为警告。
  2. 计算块范围：为每个基本块计算 source_range（从第一条语句的起始位置到最后一条语句的结束位置）。
  3. 填充邻接表：遍历所有边，填充每个块的 predecessors 和 successors 列表。

  2.3 程序切片器（slicer.py）

  2.3.1 设计原理

  程序切片是一种经典的程序分析技术。给定一个切片准则（某一行的某个变量），后向切片（backward slice）回答"哪些语句影响了这个变量在这一行的值？"，前向切片（forward slice）回答"这个变量在这一行的值会影响哪些后续语句？"

  系统实现的是基于工作列表（worklist）的过程内数据流切片算法，在 CFG 上运行。

  2.3.2 指针与结构体感知的 DEF/USE 分析（Constraint B）

  C/C++ 的赋值远不止简单的 x = expr。切片器的 _extract_def_use() 函数能够处理以下复杂左值模式：

  ┌──────────────────────┬─────────────────────────┬───────────────────────────┐
  │       代码模式       │        DEF 集合         │         USE 集合          │
  ├──────────────────────┼─────────────────────────┼───────────────────────────┤
  │ x = expr             │ {"x"}                   │ expr 中的标识符           │
  ├──────────────────────┼─────────────────────────┼───────────────────────────┤
  │ *ptr = expr          │ {"*ptr", "ptr"}         │ {"ptr"} + expr 中的标识符 │
  ├──────────────────────┼─────────────────────────┼───────────────────────────┤
  │ obj.field = expr     │ {"obj.field", "obj"}    │ expr 中的标识符           │
  ├──────────────────────┼─────────────────────────┼───────────────────────────┤
  │ ptr->field = expr    │ {"ptr->field", "ptr"}   │ expr 中的标识符           │
  ├──────────────────────┼─────────────────────────┼───────────────────────────┤
  │ arr[i] = expr        │ {"arr[]", "arr"}        │ {"i"} + expr 中的标识符   │
  ├──────────────────────┼─────────────────────────┼───────────────────────────┤
  │ ptr->arr[i].x = expr │ {"ptr->arr[].x", "ptr"} │ {"i"} + expr 中的标识符   │
  ├──────────────────────┼─────────────────────────┼───────────────────────────┤
  │ i++ / --j            │ {"i"} / {"j"}           │ {"i"} / {"j"}             │
  └──────────────────────┴─────────────────────────┴───────────────────────────┘

  DEF/USE 集合中的元素使用归一化路径表示法：
  - "x" — 简单变量
  - "*ptr" — 指针解引用
  - "obj.field" — 结构体字段
  - "ptr->field" — 指针字段
  - "arr[]" — 数组访问（下标被擦除，因为不做值追踪）

  _normalize_access_path() 函数递归遍历左值 AST 节点，构建归一化路径并收集下标中使用的索引变量。

  2.3.3 前缀匹配规则

  切片器在检查变量 v 是否出现在某个 DEF/USE 集合中时，使用前缀匹配："ptr" 匹配 "ptr"、"ptr->field"、"ptr->other"。这意味着对 ptr 的切片会包含所有触及 ptr 任何字段的语句。这是保守但安全的策略——对于漏洞检测，宁可多包含（false positive）也不能遗漏（false negative）。

  2.3.4 后向切片算法

  输入: CFG, 切片准则 (line, variable)
  输出: 相关语句集合

  1. 定位准则所在的基本块和语句索引
  2. 初始化工作列表: [(block_id, stmt_idx, variable, is_seed=True)]
  3. while 工作列表非空:
     a. 取出 (bid, sidx, var, is_seed)
     b. 从 sidx 向前扫描当前块的语句（is_seed 时跳过准则语句本身）
     c. 如果找到 DEF(var) 的语句:
        - 将该语句加入结果集
        - 将该语句的 USE 集合中的每个变量加入工作列表
        - 标记 found=True, break
     d. 如果未找到（到达块头部）:
        - 递归遍历前驱块（_propagate_to_predecessors）
        - 对于空的前驱块（join 块），继续向上追溯直到找到有语句的块

  关键实现细节：当工作列表项从前驱块传播而来时，is_seed=False，搜索从该块的最后一条语句开始（包含该语句本身）。这修复了一个早期 bug——空的 join 块会导致切片无法穿越 if/else 分支。

  2.3.5 前向切片算法

  与后向切片对称：从准则语句向后扫描，寻找 USE(var) 的语句。找到后将该语句的 DEF 集合加入工作列表继续传播。遇到 DEF(var) 的语句时停止（变量被重新定义，后续使用与原始定义无关）。

  2.3.6 ERROR 节点处理

  对于 ERROR 和 MISSING 类型的 AST 节点，_extract_def_use() 返回空集 (∅, ∅)。这意味着错误节点对切片是"透明"的——它们既不定义也不使用任何变量，不会被包含在切片中（除非它们恰好在准则行上）。

  2.4 代码分块器（chunker.py）

  2.4.1 设计原理

  分块器将解析后的函数切分为适合 RAG 检索的代码片段（Chunk）。每个 Chunk 携带完整的元数据：文件路径、函数名、行号范围、AST 节点类型集合，使得检索层可以进行精确的元数据过滤。

  2.4.2 两级分块策略

  第一级：函数级分块。 每个函数产生一个完整的 FUNCTION 类型 Chunk，包含从函数签名到闭合大括号的全部源文本。这是始终产生的基础分块。

  第二级：语义块分块。 对于超过 split_threshold（默认 30 行）的长函数，进一步拆分为 BLOCK 类型的子 Chunk：
  - 每个复合控制流语句（if_statement、for_statement、while_statement、do_statement、switch_statement）独立成块
  - 连续的简单语句（声明、表达式语句）按 max_simple_group（默认 15 行）分组
  - 每个子 Chunk 的 metadata["context"] 字段记录父函数的签名文本，为检索提供上下文

  2.4.3 Chunk 数据模型

  class Chunk(BaseModel):
      chunk_id: str          # 格式: "{file_path}:{function_name}:{start_line}-{end_line}"
      kind: ChunkKind        # FUNCTION | BLOCK | SLICE
      file_path: str
      function_name: str | None
      source_range: SourceRange
      text: str              # 原始源代码文本
      line_count: int
      ast_node_types: list[str]  # 该 Chunk 中出现的所有 AST 节点类型（排序后）
      metadata: dict[str, str]   # 可选元数据，如 "has_errors", "context"

  chunk_id 的格式设计确保了全局唯一性，同时可以直接从 ID 中解析出文件、函数和行号范围。

  2.4.4 错误节点处理

  包含 ERROR 或 MISSING 节点的 Chunk 会在 metadata 中标记 "has_errors": "true"，供下游检索和推理模块参考。错误节点的原始文本被原样保留在 Chunk 中——这是"所见即所得"原则的体现。

  2.5 宏调用处理（Constraint C）

  系统严格执行"所见即所得"策略。Tree-sitter 是具体语法树解析器，不做语义分析：

  - MACRO_FUNC(args) 在语句位置 → 被解析为 expression_statement 包含 call_expression，与普通函数调用无异
  - #define 指令 → 被解析为 preproc_def / preproc_function_def，在 CFG 构建中被 default fallback 处理
  - #ifdef / #endif → 被解析为 preproc_ifdef，同样被 default fallback 处理
  - 大写宏函数调用（如 SAFE_FREE(buf)、MEMSET(buf, 0, size)）→ 自然地作为 call_expression 进入 CFG 和 Chunk

  不做任何宏展开意味着：系统分析的是程序员实际看到的代码，行号与编辑器完全一致。

  ---
  三、Phase 2：检索层（Retrieval Layer）

  检索层实现 BM25（稀疏）与 Embedding（稠密）异构双路检索，通过 RRF（Reciprocal Rank Fusion）算法融合两路结果。它消费 Phase 1 产出的 Chunk 对象，为 Phase 3 的推理层提供相似代码模式上下文。

  3.1 C/C++ 感知分词器（tokenizer.py）

  3.1.1 设计原理

  通用的 BM25 分词器（按空格/标点分割）对代码效果很差，因为代码中的标识符命名约定（camelCase、snake_case）和多字符运算符（->、::、==）携带重要的语义信息。系统实现了专门的 C/C++ 感知分词器。

  3.1.2 分词流水线

  tokenize_code(text) 的处理流程：

  原始代码文本
      │
      ▼
  ① 剥离注释和字符串字面量
     //... 和 /* ... */ 替换为空格
     "..." 和 '...' 替换为空格
     （保留代码结构位置，不影响后续分割）
      │
      ▼
  ② 保护多字符运算符
     -> 替换为 _OP_ARROW_
     :: 替换为 _OP_SCOPE_
     == 替换为 _OP_EQ_
     （共 22 种运算符，按长度降序替换避免冲突）
      │
      ▼
  ③ 按非字母数字字符分割
     re.split(r'[^a-zA-Z0-9_]+', text)
      │
      ▼
  ④ 标识符子分割
     camelCase: maxBufferSize → ["maxbuffersize", "max", "buffer", "size"]
     snake_case: max_buffer_size → ["max_buffer_size", "max", "buffer", "size"]
     保留原始复合 token + 拆分后的子 token
      │
      ▼
  ⑤ 全部小写化
      │
      ▼
  ⑥ 还原运算符占位符
     _OP_ARROW_ → "op_arrow"
      │
      ▼
  ⑦ 过滤单字符 token（保留 C 关键字 "if"、"do"）
      │
      ▼
  最终 token 列表

  3.1.3 关键词保留

  分词器维护一个包含 80+ 个 C/C++ 关键词和危险 API 名称的集合，包括：
  - C 语言关键字：if, for, while, return, goto, switch 等
  - C++ 关键字：class, namespace, template, virtual 等
  - 内存管理 API：malloc, calloc, realloc, free
  - 危险字符串操作：strcpy, strncpy, sprintf, gets
  - 系统调用：system, exec, popen

  这些词在漏洞检测场景中携带强信号，分词器确保它们不会被子分割破坏。

  3.2 BM25 稀疏索引（bm25_index.py）

  3.2.1 实现

  基于 rank_bm25.BM25Okapi 实现。BM25（Best Matching 25）是经典的概率检索模型，通过词频（TF）、逆文档频率（IDF）和文档长度归一化计算相关性分数。

  class BM25Index:
      def build(self, chunks: list[Chunk]) -> None
      def query(self, query_text: str, top_k=20, filters=None) -> list[RetrievalResult]
      def save(self, path: str) -> None
      @classmethod
      def load(cls, path: str) -> BM25Index

  3.2.2 元数据过滤

  BM25 本身不支持元数据过滤。系统采用后评分过滤策略：先调用 get_scores() 获取所有文档的 BM25 分数，然后构建一个 0/1 掩码向量，将不满足过滤条件的文档分数置零，最后对掩码后的分数做 argsort 取 top-k。

  支持的过滤维度：
  - file_paths：限定文件路径
  - function_names：限定函数名
  - kinds：限定 Chunk 类型（function/block/slice）
  - ast_node_types：要求 Chunk 包含特定 AST 节点类型（如 call_expression）

  3.2.3 持久化

  通过 pickle 序列化三个核心数据结构：chunk_ids 列表、chunks 字典（Pydantic model_dump 后的 JSON）、tokenized_corpus（分词后的 token 列表）。加载时从 pickle 恢复数据并重建 BM25Okapi 对象。

  3.3 稠密向量索引（embedding_index.py）

  3.3.1 实现

  使用 sentence-transformers 加载本地嵌入模型，将代码文本编码为稠密向量，存储在 NumPy 数组中。查询时计算余弦相似度（向量已 L2 归一化，余弦相似度等价于点积）。

  class EmbeddingIndex:
      def __init__(self, config: RetrievalConfig)
      def build(self, chunks: list[Chunk]) -> None
      def query(self, query_text: str, top_k=20, filters=None) -> list[RetrievalResult]
      def save(self, path: str) -> None
      @classmethod
      def load(cls, path: str, config: RetrievalConfig) -> EmbeddingIndex

  3.3.2 离线安全约束（Constraint D/E/F）

  Constraint D — 遥测关闭： 虽然最终实现替换了 ChromaDB 为纯 NumPy 方案（因 Python 3.14 兼容性），但代码中仍保留了环境变量设置 ANONYMIZED_TELEMETRY=False 的防御性代码，以防未来切换回 ChromaDB。

  Constraint E — 严格离线加载：
  os.environ["HF_HUB_OFFLINE"] = "1"
  os.environ["TRANSFORMERS_OFFLINE"] = "1"
  self._model = SentenceTransformer(
      config.model_path,       # 必须是本地绝对路径
      device=device,
      trust_remote_code=False,
      local_files_only=True,
  )
  如果 model_path 为空，直接抛出 ValueError，绝不尝试从 HuggingFace Hub 下载。

  Constraint F — 动态设备分配：
  def _resolve_device(device_cfg: str) -> str:
      if device_cfg == "auto":
          import torch
          return "cuda" if torch.cuda.is_available() else "cpu"
      return device_cfg
  宿主机配备 GPU 时自动使用 CUDA 加速嵌入计算，大幅提升 build() 阶段的索引构建速度。

  3.4 RRF 融合算法（fusion.py）

  3.4.1 算法原理

  Reciprocal Rank Fusion（RRF）是一种无需训练的排名融合算法。对于文档 d，其融合分数为：

  score(d) = Σ weight_i / (k + rank_i(d))

  其中 k 是平滑常数（默认 60），rank_i(d) 是文档 d 在第 i 路检索结果中的排名，weight_i 是该路的权重。

  3.4.2 实现细节

  def reciprocal_rank_fusion(
      bm25_results, embedding_results,
      top_k=20, rrf_k=60,
      bm25_weight=1.0, embedding_weight=1.0,
  ) -> list[RetrievalResult]:

  - 遍历 BM25 结果，累加 bm25_weight / (rrf_k + rank)
  - 遍历 Embedding 结果，累加 embedding_weight / (rrf_k + rank)
  - 只出现在一路中的 Chunk 只获得该路的分数（另一路贡献为 0）
  - 按融合分数降序排列，取 top_k
  - 所有结果标记为 source=FUSED

  3.4.3 为什么选择 RRF

  RRF 的优势在于：
  1. 无需训练：不需要标注数据来学习融合权重
  2. 对分数尺度不敏感：BM25 分数和余弦相似度的数值范围完全不同，RRF 只使用排名，天然归一化
  3. 鲁棒性：即使一路检索完全失败（返回空列表），另一路的结果仍然有效

  3.5 统一检索器（retriever.py）

  Retriever 类编排整个检索流程：

  class Retriever:
      def index(self, chunks) -> IndexStats          # 构建双路索引
      def query(self, query_text, top_k, filters)    # 双路检索 + RRF 融合
      def query_bm25_only(...)                       # 仅 BM25
      def query_embedding_only(...)                  # 仅 Embedding
      def save(self) -> None                         # 持久化
      @classmethod
      def load(cls, config) -> Retriever             # 从磁盘加载

  query() 的内部流程：
  1. 计算 fetch_k = top_k × multiplier（默认 3 倍），确保融合前有足够的候选
  2. 并行执行 BM25 查询和 Embedding 查询
  3. 如果两路都有结果 → RRF 融合
  4. 如果只有一路有结果 → 直接返回该路的 top_k
  5. 如果 model_path 为空（未配置嵌入模型）→ 自动降级为 BM25-only 模式

  ---
  四、Phase 3：推理层（Reasoning Layer）

  推理层是系统的核心智能组件，实现了基于 Actor-Critic 博弈框架的对抗辩论机制。三个 LLM 智能体（Attacker、Defender、Judge）围绕同一段代码进行两轮结构化辩论，最终由 Judge 综合双方论点给出裁决。

  4.1 LLM 推理后端（llm_backend.py）

  4.1.1 GGUF 模型加载

  系统通过 llama-cpp-python 加载 GGUF 量化格式的模型文件。LLMBackend 采用懒加载模式——模型在第一次调用 generate() 时才被加载到内存。

  class LLMBackend:
      def generate(self, prompt, max_tokens=None, temperature=None) -> str
      def generate_structured(self, prompt, grammar_str, ...) -> str

  generate_structured() 是约束解码的入口：它将 GBNF 语法字符串编译为 LlamaGrammar 对象，传递给 create_completion() 的 grammar 参数，强制 LLM 的输出严格匹配指定的 JSON 结构。

  4.1.2 GPU 编译守卫（Constraint G）

  llama-cpp-python 默认以 CPU-only 模式编译安装。如果用户请求 GPU offload（n_gpu_layers != 0）但安装的是 CPU 版本，系统不会静默失败，而是：

  def _resolve_gpu_layers(config: LLMConfig) -> int:
      from llama_cpp import llama_supports_gpu_offload
      gpu_ok = llama_supports_gpu_offload()

      if config.n_gpu_layers != 0 and not gpu_ok:
          logger.warning(
              "GPU offload requested (n_gpu_layers=%d) but llama-cpp-python "
              "was compiled WITHOUT GPU support. Falling back to CPU. "
              "To enable GPU: CMAKE_ARGS=\"-DGGML_CUDA=on\" "
              "pip install llama-cpp-python --force-reinstall --no-cache-dir",
              config.n_gpu_layers,
          )
          return 0
      return config.n_gpu_layers

  这个运行时检查在模型加载时执行一次，输出明确的重编译指引，让涉密局域网的系统管理员可以直接按照提示操作。

  4.1.3 上下文窗口配置

  LLMConfig.n_ctx 默认值为 16384（而非常见的 4096）。这是因为两轮辩论流程中，Judge 的 prompt 需要包含：原始代码 + CFG 摘要 + 切片上下文 + 检索到的相似模式 + 两轮 Attacker 论点 + 两轮 Defender 论点。对于 100+ 行的函数，4096 token 的上下文窗口会溢出。

  4.1.4 Mock 后端

  MockLLMBackend 是测试专用的 LLM 替身，支持基于关键词的响应路由：

  mock = MockLLMBackend()
  mock.set_response("security auditor", attack_json)   # Attacker prompt 包含此短语
  mock.set_response("software engineer", defense_json)  # Defender prompt 包含此短语
  mock.set_response("impartial", judge_json)            # Judge prompt 包含此短语

  每个 prompt 模板中包含唯一的角色标识短语，Mock 后端据此路由到正确的预设响应。这使得完整的辩论流程可以在无真实模型的情况下进行端到端测试。

  4.2 GBNF 约束解码语法（grammars.py）

  4.2.1 设计原理

  LLM 的自由文本输出不可靠——它可能输出格式错误的 JSON、遗漏必要字段、或在字段值中使用错误的类型。GBNF（GGML BNF）是 llama.cpp 原生支持的语法约束格式，可以在 token 采样阶段强制输出匹配指定的 BNF 语法。

  系统为三个智能体分别定义了 GBNF 语法，共享一组基础原语：

  ws     ::= [ \t\n\r]*
  string ::= "\"" ([^"\\] | "\\" .)* "\""
  int    ::= "-"? [0-9]+
  float  ::= "-"? [0-9]+ ("." [0-9]+)?

  4.2.2 Attacker 语法

  强制输出包含以下字段的 JSON 对象：
  - `vulnerability
        
● 接着后处理第2步继续。                                                                                                                                                                                                                                                     
                                                                                                                                                                                                                                                                          
  ---                                                                                                                                                                                                                                                                       
  2. 计算块范围：为每个基本块计算 source_range——取块内第一条语句的起始位置和最后一条语句的结束位置。空块的 source_range 为 None。
  3. 填充邻接表：遍历所有边，为每个块填充 predecessors 和 successors 列表，支持后续切片器的双向遍历。                                                                                                                                                                       
                                                            
  2.3 程序切片器（slicer.py）

  2.3.1 设计原理

  程序切片是一种经典的程序分析技术：给定一个切片准则（某行代码中的某个变量），提取所有影响该变量值的语句（后向切片）或受该变量值影响的语句（前向切片）。在漏洞检测场景中，切片器的核心价值是：从一个危险 API 调用点（如
  strcpy）出发，向后追溯数据来源（Source），向前追踪数据去向（Sink），构建完整的数据流路径。

  系统实现的是基于工作列表（worklist）的过程内数据流切片算法，在 CFG 上运行。

  2.3.2 DEF/USE 分析（Constraint B：指针与结构体感知）

  切片算法的核心是 DEF/USE 集合计算。对于 C/C++ 代码，赋值操作远不止简单的 x = expr 形式。_extract_def_use() 函数处理以下所有情况：

  DEF 集合提取（_extract_def_targets）：

  ┌──────────────────────┬─────────────────────────┬──────────────────────────────────────┐
  │       代码模式       │        DEF 集合         │                 说明                 │
  ├──────────────────────┼─────────────────────────┼──────────────────────────────────────┤
  │ x = expr             │ {"x"}                   │ 简单标识符赋值                       │
  ├──────────────────────┼─────────────────────────┼──────────────────────────────────────┤
  │ *ptr = expr          │ {"*ptr", "ptr"}         │ 指针解引用赋值，ptr 本身也被隐式使用 │
  ├──────────────────────┼─────────────────────────┼──────────────────────────────────────┤
  │ obj.field = expr     │ {"obj.field", "obj"}    │ 结构体字段赋值                       │
  ├──────────────────────┼─────────────────────────┼──────────────────────────────────────┤
  │ ptr->field = expr    │ {"ptr->field", "ptr"}   │ 指针字段赋值                         │
  ├──────────────────────┼─────────────────────────┼──────────────────────────────────────┤
  │ arr[i] = expr        │ {"arr[]", "arr"}        │ 数组下标赋值，索引 i 进入 USE 集合   │
  ├──────────────────────┼─────────────────────────┼──────────────────────────────────────┤
  │ ptr->arr[i].x = expr │ {"ptr->arr[].x", "ptr"} │ 嵌套访问，i 进入 USE                 │
  ├──────────────────────┼─────────────────────────┼──────────────────────────────────────┤
  │ i++, --j             │ {"i"} / {"j"}           │ 更新表达式                           │
  └──────────────────────┴─────────────────────────┴──────────────────────────────────────┘

  USE 集合提取（_extract_use_vars）：
  - 赋值右侧的所有标识符
  - 条件表达式、函数参数、return 值中的标识符
  - 左值复合表达式中的基变量（如 arr[i] = x 中的 i）
  - 排除：call_expression 中的被调函数名、类型名

  归一化路径表示法：DEF/USE 集合中的元素使用归一化字符串路径：
  - "x" — 简单变量
  - "*ptr" — 解引用指针
  - "obj.field" — 结构体字段
  - "ptr->field" — 指针字段
  - "arr[]" — 数组访问（索引被擦除，因为不做值追踪）

  前缀匹配规则：切片器在检查变量 v 是否在 DEF(s) 或 USE(s) 中时，使用前缀匹配："ptr" 匹配 "ptr"、"ptr->field"、"ptr->other"。这意味着对 ptr 的切片会包含任何触及 ptr 任意字段的语句——这是保守但对漏洞检测安全的策略。

  ERROR 节点处理（Constraint A）：对于 ERROR 或 MISSING 类型的语句，_extract_def_use() 返回空集 (∅, ∅)。这些节点对切片透明——它们既不定义也不使用任何变量，除非它们恰好在切片准则行上。

  2.3.3 后向切片算法

  输入: CFG, 切片准则 (line, variable), 源代码
  输出: Slice (包含的行号集合, 语句列表, 源文本)

  1. 定位准则语句: 在 CFG 中找到覆盖目标行号的 (block_id, stmt_index)
  2. 确定种子变量集: 如果指定了 variable，种子集 = {variable}；
     否则取准则语句的 USE 集合
  3. 初始化工作列表: [(block_id, stmt_index, var, is_seed=True)] for var in 种子集
  4. 循环处理工作列表:
     a. 取出 (bid, sidx, var, is_seed)
     b. 在当前块中从 sidx 向前搜索（is_seed 时从 sidx-1 开始，否则从 sidx 开始）
     c. 找到 DEF(var) 的语句 → 加入结果集，将该语句的 USE 集合中的变量加入工作列表
     d. 如果当前块中未找到 → 递归遍历前驱块（穿越空块）
  5. 收集所有结果语句的行号，从原始源代码中提取对应行

  关键实现细节：
  - is_seed 标志区分"准则语句本身"和"从前驱块进入的语句"。准则语句本身不检查 DEF（避免自引用），但前驱块的入口语句需要检查。
  - _propagate_to_predecessors() 递归穿越空基本块（如 if/else 的 join 块），直到找到包含语句的前驱块。这确保了切片能正确穿越分支汇合点。

  2.3.4 前向切片算法

  与后向切片对称：从准则语句出发，沿 CFG 正向遍历，追踪 DEF→USE 链。当一个变量被重新定义（DEF）时，该路径上的追踪终止。_propagate_to_successors() 递归穿越空后继块。

  2.4 代码分块器（chunker.py）

  2.4.1 设计原理

  分块器将解析后的函数切分为适合 RAG 检索的代码片段（Chunk）。每个 Chunk 携带完整的元数据（文件路径、函数名、行号范围、AST 节点类型集合），使得检索层可以基于元数据进行精确过滤。

  2.4.2 两级分块策略

  Tier 1：函数级分块。每个函数无条件产生一个 FUNCTION 类型的 Chunk，包含函数的完整源文本。

  Tier 2：语义块分块。对于超过 split_threshold（默认 30 行）的长函数，进一步拆分为语义块：
  - 每个控制流结构（if_statement、for_statement、while_statement、do_statement、switch_statement）独立成块
  - 连续的简单语句（声明、表达式语句）按最大 max_simple_group（默认 15 行）分组
  - 每个语义块的 metadata["context"] 字段记录父函数的签名文本，为检索提供上下文

  2.4.3 Chunk 数据模型

  class Chunk(BaseModel):
      chunk_id: str          # 格式: "{file_path}:{function_name}:{start_line}-{end_line}"
      kind: ChunkKind        # FUNCTION | BLOCK | SLICE
      file_path: str
      function_name: str | None
      source_range: SourceRange
      text: str              # 原始源代码文本
      line_count: int
      ast_node_types: list[str]  # 块内所有 AST 节点类型（排序去重）
      metadata: dict[str, str]   # "has_errors": "true" | "context": 函数签名

  ast_node_types 字段记录了块内出现的所有命名 AST 节点类型（如 ["call_expression", "if_statement", "return_statement"]），使得检索层可以按节点类型过滤——例如只检索包含 call_expression 的块。

  2.4.4 宏调用处理（Constraint C）

  分块器严格执行"所见即所得"策略。宏调用（如 SAFE_FREE(buf)、MEMSET(buf, 0, size)）在 Tree-sitter 的解析结果中表现为普通的 call_expression，其被调函数是一个大写的 identifier。系统不做任何特殊处理——这些宏调用与普通函数调用一样被提取进 Chunk，保留原始行号和文本。

  ---
  三、Phase 2：检索层（Retrieval Layer）

  检索层实现了 BM25（稀疏）与 Embedding（稠密）异构双路检索，通过 RRF（Reciprocal Rank Fusion）算法融合两路结果。它消费 Phase 1 产出的 Chunk 对象，为 Phase 3 的推理层提供相似代码模式上下文。

  3.1 C/C++ 感知分词器（tokenizer.py）

  3.1.1 设计原理

  通用的 BM25 分词器（按空格/标点分割）对代码效果很差，因为代码中的标识符命名约定（camelCase、snake_case）和多字符运算符（->、::、==）携带重要的语义信息。系统实现了专门的 C/C++ 感知分词器。

  3.1.2 分词流水线

  tokenize_code(text) 的处理流程：

  原始代码文本
    │
    ▼ Step 1: 剥离注释和字符串字面量
    │  // 行注释、/* 块注释 */、"字符串"、'字符' → 替换为空格
    │  保留代码结构位置，不破坏行号
    │
    ▼ Step 2: 保护多字符运算符
    │  -> → _OP_ARROW_,  :: → _OP_SCOPE_,  == → _OP_EQ_ ...
    │  按长度降序替换，避免 <<= 被拆成 << 和 =
    │
    ▼ Step 3: 按非字母数字字符分割
    │  re.split(r'[^a-zA-Z0-9_]+', text)
    │
    ▼ Step 4: 标识符子分割
    │  camelCase: maxBufferSize → ["maxbuffersize", "max", "buffer", "size"]
    │  snake_case: max_buffer_size → ["max_buffer_size", "max", "buffer", "size"]
    │  保留原始复合词 + 拆分后的子词
    │
    ▼ Step 5: 全部小写化
    │
    ▼ Step 6: 还原运算符占位符
    │  _OP_ARROW_ → "op_arrow",  _OP_EQ_ → "op_eq" ...
    │
    ▼ Step 7: 过滤单字符 token
    │  保留 C 关键字中的短词（"if", "do"）
    │  过滤无意义的单字符（"a", "b", "x"）
    │
    ▼ 输出: token 列表

  3.1.3 关键词保留

  分词器维护一个包含 80+ 个 C/C++ 关键词和危险 API 名称的集合，确保这些高信号词不会被过滤：

  - C 语言关键字：if, for, while, return, goto, switch, struct, typedef 等
  - C++ 关键字：class, namespace, template, virtual, new, delete 等
  - 内存管理 API：malloc, calloc, realloc, free
  - 字符串操作 API：strcpy, strncpy, strcat, sprintf, gets
  - 危险系统调用：system, exec, popen

  这些词在漏洞检测场景中携带极高的信号量——一个包含 malloc 和 free 的代码块很可能涉及内存管理漏洞。

  3.2 BM25 稀疏索引（bm25_index.py）

  3.2.1 实现

  基于 rank_bm25.BM25Okapi 实现。BM25（Best Matching 25）是信息检索领域的经典稀疏检索算法，通过词频（TF）、逆文档频率（IDF）和文档长度归一化来计算查询与文档的相关性分数。

  class BM25Index:
      def build(self, chunks: list[Chunk]) -> None
      def query(self, query_text: str, top_k=20, filters=None) -> list[RetrievalResult]
      def save(self, path: str) -> None
      @classmethod
      def load(cls, path: str) -> BM25Index

  3.2.2 元数据过滤

  BM25 的元数据过滤采用后评分策略：先对所有文档计算 BM25 分数，然后通过掩码向量将不满足过滤条件的文档分数置零，最后取 top-k。支持的过滤维度：

  - file_paths：限定文件路径
  - function_names：限定函数名
  - kinds：限定 Chunk 类型（FUNCTION / BLOCK / SLICE）
  - ast_node_types：要求 Chunk 包含特定 AST 节点类型（如 call_expression）

  3.2.3 持久化

  通过 pickle 序列化三个核心数据结构：chunk_ids 列表、chunks 字典（JSON 格式）、tokenized_corpus（分词后的语料）。加载时从 pickle 重建 BM25Okapi 对象。

  3.3 稠密向量索引（embedding_index.py）

  3.3.1 实现

  基于 NumPy 的纯 Python 向量索引（替代 ChromaDB，避免 hnswlib 的 C++ 编译依赖）。使用 sentence-transformers 加载本地嵌入模型，将代码文本编码为稠密向量，通过余弦相似度检索。

  class EmbeddingIndex:
      def __init__(self, config: RetrievalConfig)
      def build(self, chunks: list[Chunk]) -> None
      def query(self, query_text: str, top_k=20, filters=None) -> list[RetrievalResult]
      def save(self, path: str) -> None
      @classmethod
      def load(cls, path: str, config: RetrievalConfig) -> EmbeddingIndex

  3.3.2 离线安全约束

  Constraint D — 遥测关闭：虽然最终实现替换了 ChromaDB，但系统仍在环境变量层面设置 ANONYMIZED_TELEMETRY=False，防止任何第三方库的遥测行为。

  Constraint E — 严格离线加载：

  os.environ["HF_HUB_OFFLINE"] = "1"
  os.environ["TRANSFORMERS_OFFLINE"] = "1"

  self._model = SentenceTransformer(
      config.model_path,       # 必须是本地绝对路径
      device=device,
      trust_remote_code=False,
      local_files_only=True,
  )

  三重防护：
  1. HF_HUB_OFFLINE=1 环境变量阻止 HuggingFace Hub 访问
  2. TRANSFORMERS_OFFLINE=1 环境变量阻止 Transformers 库联网
  3. local_files_only=True 参数确保只从本地路径加载

  如果 config.model_path 为空，直接抛出 ValueError，绝不回退到在线下载。

  Constraint F — 动态设备分配：

  def _resolve_device(device_cfg: str) -> str:
      if device_cfg == "auto":
          import torch
          return "cuda" if torch.cuda.is_available() else "cpu"
      return device_cfg

  当 device="auto" 时自动检测 GPU 可用性。在配备 24GB GPU 的宿主机上，嵌入计算将自动使用 CUDA 加速，大幅提升 build() 阶段的索引构建效率。

  3.3.3 检索流程

  查询时，将查询文本编码为向量，与索引中所有向量计算余弦相似度（由于向量已 L2 归一化，余弦相似度等价于点积），然后应用元数据过滤掩码，取 top-k 结果。

  3.4 RRF 融合算法（fusion.py）

  3.4.1 算法原理

  Reciprocal Rank Fusion（RRF）是一种无需训练的排名融合算法，通过倒数排名加权合并多路检索结果：

  score(d) = Σ weight_i / (k + rank_i(d))

  其中 k 是平滑常数（默认 60），rank_i(d) 是文档 d 在第 i 路检索中的排名，weight_i 是该路的权重。

  3.4.2 实现细节

  def reciprocal_rank_fusion(
      bm25_results, embedding_results,
      top_k=20, rrf_k=60,
      bm25_weight=1.0, embedding_weight=1.0,
  ) -> list[RetrievalResult]:

  - 遍历 BM25 结果，累加 bm25_weight / (rrf_k + rank)
  - 遍历 Embedding 结果，累加 embedding_weight / (rrf_k + rank)
  - 只出现在一路中的文档，另一路贡献为 0
  - 按融合分数降序排列，取 top-k
  - 所有结果标记为 source=FUSED

  3.4.3 为什么选择 RRF

  RRF 的优势在于：
  1. 无需训练：不需要标注数据来学习融合权重
  2. 对分数尺度不敏感：BM25 分数和余弦相似度的数值范围完全不同，RRF 只使用排名，天然归一化
  3. 鲁棒性：即使一路检索完全失败（返回空结果），另一路的结果仍然有效

  3.5 统一检索器（retriever.py）

  Retriever 类编排整个检索流程：

  class Retriever:
      def index(self, chunks: list[Chunk]) -> IndexStats
      def query(self, query_text, top_k=None, filters=None) -> list[RetrievalResult]
      def query_bm25_only(self, ...) -> list[RetrievalResult]
      def query_embedding_only(self, ...) -> list[RetrievalResult]
      def save(self) -> None
      @classmethod
      def load(cls, config: RetrievalConfig) -> Retriever

  query() 的编排逻辑：
  1. BM25 查询，获取 top_k × bm25_top_k_multiplier 个候选
  2. Embedding 查询，获取 top_k × embedding_top_k_multiplier 个候选
  3. 如果两路都有结果 → RRF 融合
  4. 如果只有一路有结果 → 直接返回该路 top-k
  5. 如果 model_path 为空（无嵌入模型）→ 自动降级为 BM25-only 模式

  ---
  四、Phase 3：推理层（Reasoning Layer）

  推理层是系统的核心智能组件，实现了基于 Actor-Critic 博弈框架的对抗辩论机制。三个 LLM 智能体（Attacker、Defender、Judge）围绕代码漏洞展开两轮结构化辩论，最终由 Judge 综合双方论点给出裁决。

  4.1 LLM 推理后端（llm_backend.py）

  4.1.1 GGUF 模型加载

  系统通过 llama-cpp-python 加载 GGUF 量化格式的大语言模型。LLMBackend 采用懒加载模式——模型在第一次调用 generate() 时才加载，避免不必要的内存占用。

  class LLMBackend:
      def generate(self, prompt, max_tokens=None, temperature=None) -> str
      def generate_structured(self, prompt, grammar_str, ...) -> str

  4.1.2 GPU 编译守卫（Constraint G）

  llama-cpp-python 默认安装的是 CPU-only 版本。要使用 CUDA 加速，用户必须以特定编译参数重新安装。系统在模型加载时通过 _resolve_gpu_layers() 执行运行时检查：

  def _resolve_gpu_layers(config: LLMConfig) -> int:
      from llama_cpp import llama_supports_gpu_offload
      gpu_ok = llama_supports_gpu_offload()

      if config.n_gpu_layers != 0 and not gpu_ok:
          logger.warning(
              "GPU offload requested (n_gpu_layers=%d) but llama-cpp-python "
              "was compiled WITHOUT GPU support. Falling back to CPU. "
              "To enable GPU: CMAKE_ARGS=\"-DGGML_CUDA=on\" "
              "pip install llama-cpp-python --force-reinstall --no-cache-dir",
              config.n_gpu_layers,
          )
          return 0
      return config.n_gpu_layers

  这个守卫确保：
  - 如果用户请求了 GPU（n_gpu_layers != 0）但二进制不支持 → 打印明确的重编译指引，自动降级到 CPU
  - 如果二进制支持 GPU → 正常使用请求的 n_gpu_layers
  - 检查只在模型加载时执行一次

  4.1.3 上下文窗口配置

  LLMConfig.n_ctx 默认值为 16384（而非常见的 4096）。这是因为两轮辩论流程中，Judge 的 prompt 需要包含：原始代码 + CFG 摘要 + 切片上下文 + 检索到的相似模式 + 两轮 Attacker 论点 + 两轮 Defender 论点。对于一个 100 行的函数，这些内容拼接后很容易超过 4096 token。16384 为
  400 行以内的函数提供了充足的上下文空间。

  4.1.4 MockLLMBackend

  MockLLMBackend 是用于测试的模拟后端，无需加载真实模型。它支持基于关键词的响应路由：

  mock = MockLLMBackend()
  mock.set_response("security auditor", attack_json)   # Attacker prompt 包含此短语
  mock.set_response("software engineer", defense_json)  # Defender prompt 包含此短语
  mock.set_response("impartial", judge_json)            # Judge prompt 包含此短语

  每个 prompt 模板中包含唯一的角色标识短语，使得 mock 可以根据 prompt 内容自动路由到正确的预设响应。

  4.2 GBNF 约束解码语法（grammars.py）

  4.2.1 设计原理

  大语言模型的自由文本输出不可靠——它可能输出格式错误的 JSON、遗漏必要字段、或在字段值中使用错误的类型。GBNF（GGML BNF）是 llama.cpp 原生支持的语法约束机制，它在 token 采样阶段强制模型输出符合指定 BNF 语法的文本。

  这意味着：只要语法定义正确，模型的输出就一定是合法的 JSON，且包含所有必要字段，且字段值类型正确。这比"生成后解析+重试"的策略更可靠、更高效。

  4.2.2 共享原语

  三套语法共享基础原语定义：

  ws     ::= [ \t\n\r]*
  string ::= "\"" ([^"\\] | "\\" .)* "\""
  int    ::= "-"? [0-9]+
  float  ::= "-"? [0-9]+ ("." [0-9]+)?

  4.2.3 Attacker 语法

  强制输出包含以下字段的 JSON 对象：

  root ::= "{" ws
    "\"vulnerability_type\"" ws ":" ws string ws "," ws
    "\"confidence\""         ws ":" ws float  ws "," ws
    "\"source\""             ws ":" ws point  ws "," ws
    "\"sink\""               ws ":" ws point  ws "," ws
    "\"data_flow_path\""     ws ":" ws point-array ws "," ws
    "\"reasoning\""          ws ":" ws string ws
  "}"

  point ::= "{" ws
    "\"line\""        ws ":" ws int    ws "," ws
    "\"code\""        ws ":" ws string ws "," ws
    "\"description\"" ws ":" ws string ws
  "}"

  point-array ::= "[" ws "]" | "[" ws point (ws "," ws point)* ws "]"

  4.2.4 Defender 语法

  defense-verdict ::= "\"safe\"" | "\"partially_mitigated\"" | "\"unmitigated\""

  verdict 字段被约束为三个枚举值之一，模型无法输出其他值。

  4.2.5 Judge 语法

  verdict         ::= "\"VULNERABLE\"" | "\"SAFE\"" | "\"UNCERTAIN\""
  nullable-string ::= string | "null"
  role            ::= "\"source\"" | "\"propagation\"" | "\"sink\""

  Judge 的 vulnerability_type 字段允许 null（当判定为 SAFE 时），source_sink_path 中每个点的 role 被约束为三个枚举值。

  4.3 Prompt 模板（prompts.py）

  4.3.1 代码行号标注

  所有 prompt 中的代码都通过 _numbered_code() 函数添加物理行号前缀：

     1 | int resource_handler(int flag) {
     2 |     int *buffer = NULL;
     3 |     buffer = (int *)malloc(MAX_SIZE * sizeof(int));
     ...

  每个 prompt 的末尾都包含明确指令："Use ONLY line numbers that appear in the code listing above."，引导模型只引用实际存在的行号。

  4.3.2 五个 Prompt 模板

  Round 1 — Attacker 初始分析 (build_attacker_prompt)：
  - 角色："You are a senior security auditor (Attacker role)"
  - 输入：代码（带行号）+ CFG 摘要 + 切片上下文 + 检索到的相似模式（最多 5 个）
  - 任务：识别漏洞类型（CWE ID）、定位 Source 和 Sink、追踪数据流路径、给出置信度

  Round 1 — Defender 初始防御 (build_defender_prompt)：
  - 角色："You are a senior software engineer (Defender role)"
  - 输入：代码 + Attacker 的论点 JSON + 检索到的相似模式（最多 3 个）
  - 任务：评估漏洞声明的有效性、列举缓解措施（边界检查、空指针检查等）、指出
           
● 接着后向切片算法第4步继续。                                                                                                                                                                                                                                               
                                                                                                                                                                                                                                                                          
  ---                                                                                                                                                                                                                                                                       
  4. 循环处理工作列表:
  a. 取出 (bid, sidx, var, is_seed)                                                                                                                                                                                                                                         
  b. 如果 (bid, sidx, var) 已访问过，跳过                   
  c. 在当前块中从 sidx 向前搜索（is_seed 时从 sidx-1 开始，否则从 sidx 开始）
  d. 找到第一条 DEF 了 var 的语句 → 加入结果集，将该语句的 USE 集合中的变量加入工作列表
  e. 如果当前块中未找到 DEF → 通过 _propagate_to_predecessors() 递归穿越空前驱块，直到找到有语句的前驱块，将其加入工作列表
  5. 收集所有结果语句的行号，从原始源代码中提取对应行文本

  **空块穿越机制**：CFG 中存在大量空的 join 块（如 if/else 的汇合点）。当后向搜索到达一个空块时，`_propagate_to_predecessors()` 递归地沿前驱链向上遍历，直到找到包含语句的块。这确保了切片能正确穿越 if/else 分支——例如从 `return result` 后向切片时，能穿过空的 join
  块到达三个分支中的 `result = 1`、`result = -1`、`result = 0`。

  #### 2.3.4 前向切片算法

  前向切片与后向切片对称：从准则语句出发，沿 CFG 的后继方向搜索。对每条语句检查其 USE 集合是否包含目标变量；如果匹配，将该语句的 DEF 集合中的变量加入工作列表继续追踪。当目标变量被重新定义（DEF）时，停止在该路径上的传播。同样使用 `_propagate_to_successors()`
  穿越空后继块。

  ### 2.4 代码分块器（chunker.py）

  #### 2.4.1 设计原理

  分块器将解析后的函数切分为适合 RAG 检索的代码片段（Chunk）。每个 Chunk 携带完整的元数据：文件路径、函数名、行号范围、AST 节点类型集合，使得检索层可以进行精确的元数据过滤。

  #### 2.4.2 两级分块策略

  **Tier 1：函数级分块**——每个函数产生一个完整的 FUNCTION 类型 Chunk，始终生成。

  **Tier 2：语义块分块**——对于超过 `split_threshold`（默认 30 行）的长函数，进一步拆分为 BLOCK 类型 Chunk：
  - 每个复合控制结构（`if_statement`、`for_statement`、`while_statement`、`do_statement`、`switch_statement`）独立成块
  - 连续的简单语句（声明、表达式语句）按 `max_simple_group`（默认 15 行）分组
  - 每个 BLOCK Chunk 的 `metadata["context"]` 字段记录父函数的签名文本，为检索提供上下文

  #### 2.4.3 Chunk 数据模型

  ```python
  class Chunk(BaseModel):
      chunk_id: str          # 格式: "{file_path}:{function_name}:{start_line}-{end_line}"
      kind: ChunkKind        # FUNCTION | BLOCK | SLICE
      file_path: str
      function_name: str | None
      source_range: SourceRange
      text: str              # 原始源代码文本
      line_count: int
      ast_node_types: list[str]   # 排序后的 AST 节点类型集合
      metadata: dict[str, str]    # "has_errors", "context" 等

  chunk_id 的设计确保了跨索引的唯一标识——同一个 Chunk 在 BM25 索引和 Embedding 索引中使用相同的 ID，使 RRF 融合能正确合并结果。

  2.4.4 错误节点处理（Constraint A）

  包含 ERROR 或 MISSING 节点的 Chunk 会在 metadata 中标记 "has_errors": "true"。这些 Chunk 仍然被正常索引和检索——它们包含的是原始源文本，行号完全保真——但下游阶段可以根据此标记降低其优先级或添加额外警告。

  2.5 解析层 CLI

  # 基本解析
  python -m mmrag.parsing tests/fixtures/sample.c --output text

  # JSON 输出（包含完整 AST、CFG、Chunk 数据）
  python -m mmrag.parsing tests/fixtures/sample.c --output json

  # 后向切片
  python -m mmrag.parsing tests/fixtures/sample.c --slice 28:result --direction backward

  # 前向切片
  python -m mmrag.parsing tests/fixtures/sample.c --slice 82:buffer --direction forward

  ---
  三、Phase 2：检索层（Retrieval Layer）

  检索层实现 BM25（稀疏）与 Embedding（稠密）异构双路检索，通过 RRF（Reciprocal Rank Fusion）算法融合两路结果。它消费解析层产出的 Chunk 对象，为推理层提供"相似代码模式"上下文。

  3.1 C/C++ 感知分词器（tokenizer.py）

  3.1.1 设计原理

  通用的 BM25 分词器（按空格/标点分割）对代码效果很差——maxBufferSize 会被当作一个不可分割的 token，导致搜索 buffer 时无法命中。系统实现了专门针对 C/C++ 代码的分词管线。

  3.1.2 分词管线（6 步）

  原始代码文本
    │
    ▼ Step 1: 剥离注释和字符串字面量
    │  // 行注释、/* 块注释 */、"字符串"、'字符' → 替换为空格
    │  保留代码结构位置，不破坏行号
    ▼ Step 2: 保护多字符运算符
    │  -> :: << >> <= >= == != && || += -= 等
    │  替换为占位符 _OP_ARROW_ _OP_SCOPE_ 等
    ▼ Step 3: 按非字母数字字符分割
    │  re.split(r'[^a-zA-Z0-9_]+', text)
    ▼ Step 4: camelCase 和 snake_case 拆分
    │  maxBufferSize → ["maxbuffersize", "max", "buffer", "size"]
    │  max_buffer_size → ["max_buffer_size", "max", "buffer", "size"]
    │  保留原始复合 token + 拆分后的子 token
    ▼ Step 5: 全部小写化
    ▼ Step 6: 还原运算符占位符 + 过滤
    │  _OP_ARROW_ → "op_arrow"
    │  过滤单字符 token（除 "if"、"do" 等 C 关键字外）
    │
    ▼ 最终 token 列表

  3.1.3 关键词保留

  分词器内置了完整的 C/C++ 关键字表和危险 API 名称表（malloc、free、strcpy、sprintf、gets、system 等）。这些 token 在 BM25 检索中携带强烈的漏洞信号——当查询包含 malloc free buffer 时，包含这些 API 调用的代码块会获得更高的 BM25 分数。

  3.2 BM25 稀疏索引（bm25_index.py）

  3.2.1 算法

  使用 rank_bm25.BM25Okapi 实现，这是 BM25 的标准变体，参数为 k1=1.5, b=0.75（库默认值）。索引构建过程：

  1. 对每个 Chunk 的 text 字段执行 C/C++ 分词
  2. 将分词后的 token 列表作为文档语料库传入 BM25Okapi
  3. 维护 chunk_ids 列表和 chunks 字典的平行映射

  3.2.2 查询与过滤

  查询流程：
  1. 对查询文本执行 tokenize_query()（跳过注释/字符串剥离步骤）
  2. 调用 bm25.get_scores(query_tokens) 获取所有文档的 BM25 分数
  3. 如果指定了 MetadataFilter，构建过滤掩码（numpy 数组），将不匹配的文档分数置零
  4. np.argsort 取 top-k 结果

  元数据过滤支持四个维度：
  - file_paths: 限定文件路径
  - function_names: 限定函数名
  - kinds: 限定 Chunk 类型（function/block/slice）
  - ast_node_types: 要求 Chunk 包含特定 AST 节点类型（如 call_expression）

  3.2.3 持久化

  通过 pickle 序列化三个核心数据结构：chunk_ids 列表、chunks 字典（Pydantic model_dump 后的 JSON）、tokenized_corpus（分词后的 token 列表）。加载时重建 BM25Okapi 对象。

  3.3 稠密向量索引（embedding_index.py）

  3.3.1 架构选择

  最初设计使用 ChromaDB 作为向量数据库，但由于 chroma-hnswlib 在 Python 3.14 上没有预编译 wheel（需要 C++ 编译环境），最终改为纯 NumPy 实现：嵌入向量存储为 np.ndarray，余弦相似度通过矩阵乘法计算（向量已 L2
  归一化）。这一方案零额外依赖、完全离线友好，且对于单文件/小项目规模的索引完全够用。

  3.3.2 离线安全约束

  Constraint D — 遥测关闭：虽然最终未使用 ChromaDB，但代码中保留了遥测关闭的模式作为防御性编程示范。

  Constraint E — 严格离线模型加载：

  def _ensure_model(self):
      # 双重防护：环境变量 + 参数
      os.environ["HF_HUB_OFFLINE"] = "1"
      os.environ["TRANSFORMERS_OFFLINE"] = "1"

      if not self._config.model_path:
          raise ValueError("config.model_path is required for offline deployment.")

      self._model = SentenceTransformer(
          self._config.model_path,    # 必须是本地绝对路径
          device=device,
          trust_remote_code=False,    # 禁止执行不受信任的模型代码
          local_files_only=True,      # 禁止回退到 Hub 下载
      )

  如果 model_path 为空，直接抛出 ValueError，绝不尝试从 HuggingFace Hub 下载。环境变量 HF_HUB_OFFLINE 和 TRANSFORMERS_OFFLINE 作为第二道防线，即使代码中有其他路径意外触发了 Hub 访问，也会被环境变量拦截。

  Constraint F — 动态设备分配：

  def _resolve_device(device_cfg: str) -> str:
      if device_cfg == "auto":
          import torch
          return "cuda" if torch.cuda.is_available() else "cpu"
      return device_cfg

  不硬编码 device="cpu"。当宿主机配备 GPU 时，嵌入计算自动使用 CUDA 加速，大幅提升 build() 阶段对海量代码块的索引效率。

  3.3.3 索引构建与查询

  构建：分批（embedding_batch_size=64）编码 Chunk 文本，L2 归一化后堆叠为 (N, D) 的 numpy 矩阵。

  查询：编码查询文本为向量，与索引矩阵做矩阵乘法得到余弦相似度分数，应用元数据过滤掩码后取 top-k。

  3.4 RRF 融合算法（fusion.py）

  3.4.1 算法原理

  Reciprocal Rank Fusion（RRF）是一种无需训练的排名融合方法。其核心公式：

  score(d) = Σ weight_i / (k + rank_i(d))

  其中 k 是平滑常数（默认 60），rank_i(d) 是文档 d 在第 i 个检索器中的排名，weight_i 是该检索器的权重。

  3.4.2 实现细节

  def reciprocal_rank_fusion(bm25_results, embedding_results, top_k=20, rrf_k=60,
                             bm25_weight=1.0, embedding_weight=1.0):
      scores = {}
      for r in bm25_results:
          scores[r.chunk_id] = bm25_weight / (rrf_k + r.rank)
      for r in embedding_results:
          scores[r.chunk_id] = scores.get(r.chunk_id, 0.0) + embedding_weight / (rrf_k + r.rank)
      # 按融合分数降序排列，取 top_k

  关键设计点：
  - 只出现在一路结果中的 Chunk 仍然参与排名（另一路贡献为 0）
  - bm25_weight 和 embedding_weight 可调，允许根据场景偏向词法匹配或语义匹配
  - 融合后的结果标记为 RetrievalSource.FUSED

  3.4.3 为什么选择 RRF

  相比学习型融合（如 LambdaMART），RRF 的优势在于：
  - 无需训练数据——在涉密环境中获取标注数据极其困难
  - 对两路检索器的分数尺度不敏感——BM25 分数和余弦相似度的数值范围完全不同，RRF 只使用排名
  - 实现简单、确定性强、可解释

  3.5 统一检索器（retriever.py）

  Retriever 类编排整个检索流程：

  query() 流程:
    1. BM25 查询 (fetch_k = top_k × bm25_top_k_multiplier)
    2. Embedding 查询 (fetch_k = top_k × embedding_top_k_multiplier)
    3. RRF 融合两路结果
    4. 返回 top_k 融合结果

  降级策略:
    - 如果没有配置 model_path → 跳过 Embedding，仅用 BM25
    - 如果 BM25 索引为空 → 仅用 Embedding
    - 如果两路都为空 → 返回空列表

  Retriever 还提供 query_bm25_only() 和 query_embedding_only() 方法，允许单独使用某一路检索器进行调试或对比实验。

  3.6 检索层 CLI

  # 索引文件
  python -m mmrag.retrieval index tests/fixtures/sample.c --bm25-path ./index/bm25.pkl

  # BM25 查询
  python -m mmrag.retrieval query "malloc free buffer overflow" --mode bm25 --top-k 5

  # 带元数据过滤的查询
  python -m mmrag.retrieval query "strcpy buffer" --filter-func resource_handler --mode bm25

  # 查看索引统计
  python -m mmrag.retrieval stats --bm25-path ./index/bm25.pkl

  ---
  四、Phase 3：推理层（Reasoning Layer）

  推理层是系统的核心智能组件，实现了基于 Actor-Critic 博弈框架的对抗辩论机制。三个 LLM 智能体（Attacker、Defender、Judge）围绕同一段代码进行两轮结构化辩论，最终产出带有完整证据链的漏洞报告。

  4.1 LLM 推理后端（llm_backend.py）

  4.1.1 GGUF 模型加载

  系统使用 llama-cpp-python 作为推理后端，直接加载 GGUF 量化格式的模型文件。LLMBackend 类采用懒加载模式——模型在第一次调用 generate() 时才被加载到内存。

  class LLMConfig(BaseModel):
      model_path: str = ""       # GGUF 文件的本地绝对路径
      n_gpu_layers: int = -1     # -1 表示全部层卸载到 GPU
      n_ctx: int = 16384         # 上下文窗口大小
      n_threads: int = 4         # CPU 线程数
      temperature: float = 0.1   # 低温度确保输出确定性
      max_tokens: int = 2048     # 单次生成最大 token 数
      seed: int = 42             # 随机种子，确保可复现
      device: str = "auto"       # "auto" | "cpu" | "gpu"

  n_ctx=16384 的设计理由：2 轮辩论流程中，Judge 的 prompt 需要包含：原始代码（~200 行 × 40 字符）+ CFG 摘要 + 切片上下文 + 检索到的相似代码（5 个 Chunk）+ Round 1 的 Attack 和 Defense 完整 JSON + Round 2 的 Attack 和 Defense 完整 JSON。以 n_ctx=4096
  计算，对任何非平凡函数都会溢出。16384 为 ~400 行函数的完整辩论提供了充足空间。

  4.1.2 GPU 编译守卫（Constraint G）

  llama-cpp-python 默认以 CPU-only 模式编译安装。如果用户请求 GPU 卸载但二进制文件不支持，不会报错而是静默回退到 CPU——这在性能敏感的场景中是一个隐蔽的陷阱。

  系统在模型加载时执行显式检查：

  def _resolve_gpu_layers(config: LLMConfig) -> int:
      from llama_cpp import llama_supports_gpu_offload
      gpu_ok = llama_supports_gpu_offload()

      if config.n_gpu_layers != 0 and not gpu_ok:
          logger.warning(
              "GPU offload requested (n_gpu_layers=%d) but llama-cpp-python was compiled "
              "WITHOUT GPU support. Falling back to CPU (n_gpu_layers=0). "
              "To enable GPU, reinstall with:\n"
              '  CMAKE_ARGS="-DGGML_CUDA=on" pip install llama-cpp-python '
              "--force-reinstall --no-cache-dir",
              config.n_gpu_layers,
          )
          return 0
      return config.n_gpu_layers

  这个守卫确保：
  1. 如果 GPU 不可用，给出明确的警告和修复指令，而非静默降级
  2. 涉密局域网的系统管理员可以根据日志中的指令正确编译安装

  4.1.3 约束解码

  generate_structured() 方法接受一个 GBNF 语法字符串，通过 llama-cpp-python 的原生语法约束功能，强制 LLM 的输出严格匹配指定的 JSON 结构：

  def generate_structured(self, prompt, grammar_str, ...):
      grammar = LlamaGrammar.from_string(grammar_str)
      result = model.create_completion(prompt, grammar=grammar, ...)
      return result["choices"][0]["text"]

  这消除了 LLM 输出格式不合规的问题——无论模型的"创造力"如何，输出一定是可解析的 JSON。

  4.1.4 MockLLMBackend

  MockLLMBackend 是用于测试的模拟后端，无需加载真实模型。它支持基于关键词的响应路由：

  mock = MockLLMBackend()
  mock.set_response("security auditor", attack_json)   # Attacker prompt 包含此短语
  mock.set_response("software engineer", defense_json)  # Defender prompt 包含此短语
  mock.set_response("impartial", judge_json)            # Judge prompt 包含此短语

  每个 prompt 模板中包含唯一的角色标识短语，使得 mock 可以根据 prompt 内容自动路由到正确的预设响应。call_count 属性记录总调用次数，用于验证辩论流程的完整性（2 轮辩论 = 5 次 LLM 调用）。

  4.2 GBNF 约束语法（grammars.py）

  4.2.1 GBNF 简介

  GBNF（GGML BNF）是 llama.cpp 使用的语法约束格式，基于 BNF（巴科斯-诺尔范式）。它定义了 LLM 输出必须遵循的形式语法——在每一步 token 采样时，只有符合语法的 token 才会被考虑。

  4.2.2 共享原语

  三套语法共享以下基础规则：

  ws     ::= [ \t\n\r]*                          # 可选空白
  string ::= "\"" ([^"\\] | "\\" .)* "\""        # JSON 字符串
  int    ::= "-"? [0-9]+                          # 整数
  float  ::= "-"? [0-9]+ ("." [0-9]+)?           # 浮点数

  4.2.3 Attacker 语法

  强制输出匹配 AttackArgument 模型的 JSON：

  root ::= "{" ws
    "\"vulnerability_type\"" ws ":" ws string ws "," ws
    "\"confidence\"" ws ":" ws float ws "," ws
    "\"source\"" ws ":" ws point ws "," ws
    "\"sink\"" ws ":" ws point ws "," ws
    "\"data_flow_path\"" ws ":" ws point-array ws "," ws
    "\"reasoning\"" ws ":" ws string ws
  "}"

  point ::= "{" ws
    "\"line\"" ws ":" ws int ws "," ws
    "\"code\"" ws ":" ws string ws "," ws
    "\"description\"" ws ":" ws string ws
  "}"

  point-array ::= "[" ws "]" | "[" ws point (ws "," ws point)* ws "]"

  这确保 Attacker 的输出一定包含：漏洞类型字符串、置信度浮点数、Source 点（带行号）、Sink 点（带行号）、数据流路径数组、推理说明。

  4.2.4 Defender 语法

  defense-verdict ::= "\"safe\"" | "\"partially_mitigated\"" | "\"unmitigated\""

  Defender 的 verdict 字段被约束为三个枚举值之一，不允许 LLM 自由发挥。

  4.2.5 Judge 语法

  verdict ::= "\"VULNERABLE\"" | "\"SAFE\"" | "\"UNCERTAIN\""
  nullable-string ::= string | "null"
  role ::= "\"source\"" | "\"propagation\"" | "\"sink\""

  Judge 的输出中，verdict 限定为三个枚举值，vulnerability_type 允许为 null（当判定为 SAFE 时），source_sink_path 中每个点的 role 限定为三个角色之一。

  4.3 Prompt 模板（prompts.py）

  4.3.1 设计原则

  所有 prompt 遵循以下原则：
  1. 带行号的代码展示：通过 _numbered_code() 函数为代码添加行号前缀（   1 | int x = 0;），使 LLM 能准确引用物理行号
  2. 明确的角色设定：每个 prompt 开头声明智能体角色（"senior security auditor"、"senior software engineer"、"impartial Judge"）
  3. 结构化指令：以编号列表形式给出具体任务步骤
  4. 行号约束提醒：每个 prompt 末尾都包含 "Use ONLY line numbers that appear in the code listing above"

  4.3.2 五个 Prompt 模板

  ┌────────────────────────────────┬──────────────────┬─────────────────────────────────────────┬──────────────┐
  │              模板              │       角色       │                  输入                   │     用途     │
  ├────────────────────────────────┼──────────────────┼─────────────────────────────────────────┼──────────────┤
  │ build_attacker_prompt          │ Attacker Round 1 │ 代码 + 检索上下文 + CFG 摘要 + 切片信息 │ 初始漏洞分析 │
  ├────────────────────────────────┼──────────────────┼─────────────────────────────────────────┼──────────────┤
  │ build_defender_prompt          │ Defender Round 1 │ 代码 + 检索上下文 + Attacker 论点       │ 反驳漏洞主张 │
  ├────────────────────────────────┼──────────────────┼─────────────────────────────────────────┼──────────────┤
  │ build_attacker_rebuttal_prompt │ Attacker Round 2 │ 代码 + Defender 论点 + 原始攻击         │ 回应防御论点 │
  ├────────────────────────────────┼──────────────────┼─────────────────────────────────────────┼──────────────┤
  │ build_defender_rebuttal_prompt │ Defender Round 2 │ 代码 + Attacker 反驳 + 原始防御         │ 最终防御陈述 │
  ├────────────────────────────────┼──────────────────┼─────────────────────────────────────────┼──────────────┤
  │ build_judge_prompt             │ Judge            │ 代码 + 完整辩论记录                     │ 综合裁决     │
  └────────────────────────────────┴──────────────────┴─────────────────────────────────────────┴──────────────┘

  4.3.3 上下文注入

  Attacker 的 prompt 包含四类上下文信息：

  1. 代码本身：带行号的函数源代码
  2. CFG 摘要：由 build_cfg_summary() 生成的紧凑文本（如 "Blocks: 10, Edges: 12; Edge types: goto=2, return=1; Contains goto"）
  3. 切片上下文：从危险 API 调用点出发的后向切片结果，展示数据流来源
  4. 检索上下文：通过 Retriever 检索到的 top-5 相似代码片段

  4.4 智能体实现（agents.py）

  4.4.1 三个智能体

  AttackerAgent：
  - analyze(code, context_chunks, cfg_summary, slice_info) → AttackArgument：Round 1 攻击
  - rebut(code, defender_argument, original_attack) → AttackArgument：Round 2 反驳

  DefenderAgent：
  - defend(code, context_chunks, attacker_argument) → DefenseArgument：Round 1 防御
  - rebut(code, attacker_rebuttal, original_defense) → DefenseArgument：Round 2 反驳

  JudgeAgent：
  - judge(code, debate_record) → JudgeVerdict：最终裁决

  4.4.2 容错与重试机制

  每个智能体的 _call() 方法实现两级容错：

  第一次尝试: temperature=0.1 (配置默认值)
    ├── 成功 → 解析 JSON → 返回类型化结果
    └── 失败 (JSON 解析错误或验证错误)
         │
         ▼
  第二次尝试: temperature=0.3 (略高温度，增加多样性)
    ├── 成功 → 解析 JSON → 返回类型化结果
    └── 失败
         │
         ▼
  返回保守默认值:
    Attacker → AttackArgument(reasoning="Analysis failed...")
    Defender → DefenseArgument(reasoning="Defense failed...")
    Judge    → JudgeVerdict(verdict=UNCERTAIN, summary="Judgment failed...")

  _parse_json_safe() 函数额外处理 LLM 输出中可能的前缀文本（如 "Here is the JSON