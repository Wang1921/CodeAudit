# CodeAudit - 双轨制多智能体代码审计系统 (Multi-Agent Code Auditing System)

CodeAudit 是一个**高度自动化、具备专家级推理能力**的代码审计引擎。系统通过 **Python 异步引擎** 驱动，结合 **Claude Agent SDK**（调用本地 Claude Code CLI）和 **Semgrep 静态扫描器**，利用多个具有特定安全专业领域的大模型智能体 (Agents) 进行协同作战。

系统采用独特的**双轨制（自底向上与自顶向下并行）**架构，通过 **A2A 文件系统消息总线** 实现 Agent 间通信，能够发现技术型漏洞（如 SQL 注入、路径遍历）和业务逻辑漏洞（如 IDOR 越权、条件竞争）。

## 🌟 核心特性 (Core Features)

*   **双轨并行审查 (Dual-Track Auditing)**
    *   **技术轨道 (Bottom-Up)**: 通过 Semgrep 静态扫描器发现底层危险函数 (Sinks)，向上逆向追踪。覆盖 **~180 条 rule_id（83 个 yaml），跨 Java / Python / C / C++ 四语言**：注入类、反序列化、SSRF、XXE、加密、JWT、TLS、信息泄露、硬编码凭据、缓冲区溢出、格式化字符串、整数溢出、UAF、Double Free、TOCTOU 等内存安全类。
    *   **业务轨道 (Top-Down)**: 从 API 路由入口向下正向推演，专攻 IDOR（越权）、Privilege Escalation、Authentication Bypass、Open Redirect 等业务逻辑漏洞。
    *   **互不抢任务**：LogicAuditor 遇到技术类形态（SQL Injection / Path Traversal / XSS / SSRF / XXE / Unsafe Deserialization / Command Injection 等）强制返回 DEFENDED，让 Sink 路径处理。技术类、业务类各司其职。
*   **CodeGraph 代码智能增强 (CodeGraph Integration)**
    *   集成 **CodeGraph** 本地代码智能库，通过 MCP 协议为 Agent 提供代码结构查询能力。
    *   引擎启动时自动在目标项目目录执行 `codegraph init -i` 构建索引。
    *   Agent 统一使用 `codegraph` 工具（codegraph_explore / codegraph_callers / codegraph_callees 等）进行调用链追踪，**禁止仅凭方法名推断变量赋值来源**。
    *   预期收益：工具调用减少 58%，Token 消耗降低 40~60%，审计耗时减少 20~30%。
*   **文件系统即总线 (A2A over File System IPC)**
    *   采用本地文件系统目录（`.a2a_bus/`）作为异步消息总线。
    *   Agent 之间通过读写强类型的 JSON 信封 (TaskRequest / TaskResult) 进行任务流转，具备极强的可观测性和容错性。
*   **Claude Agent SDK 调用本地 Claude Code CLI**
    *   Python 引擎管理多个 Claude Code CLI 会话。默认最大 5 个并发，**引擎启动时按发现的微服务数自动扩容**至 `max(5, 服务数)`。
    *   细粒度锁：不同 `cwd` 的冷启动并行，同 `cwd` 的热路径查询无全局串行。
    *   双回收策略：LRU（容量满时淘汰最旧）+ Session 空闲监控。
    *   通过 `claude-agent-sdk` 包调用本地 Claude Code CLI 进行代码分析。
    *   **超时控制**：默认 `max_turns=None`（无限制）、`max_budget_usd=None`（无限制），通过 `PER_AGENT_TIMEOUT` 实现 per-agent 超时配置（如 LogicAuditor: 480s，其他: 300s）。
*   **结构化输出与强校验 (Structured Output)**
    *   每个 Agent 的 `output_schema` 通过 **Claude Agent SDK 的 `output_format` 配置**指定 JSON Schema，服务端返回结构化输出并自动校验。
    *   `ResultMessage.structured_output` 包含服务端校验通过的 JSON，引擎直接读取。
    *   客户端二次校验：用 jsonschema 验证 structured_output，确保数据合规。
    *   降级处理：如果 structured_output 为空，从 response 文本提取 JSON。
    *   **SDK 无内置重试**：schema 验证失败时 SDK 直接返回 `structured_output=None`，由业务层（CodeAudit 引擎）处理重试或降级提取。
    *   所有 Agent 赋 `Read, Bash, Glob, Grep, Skill, Write` 工具（`base_tools` 同步含 `write`），`permission_mode=bypassPermissions` 全量放行，Agent 可直接读写落盘报告 / 执行命令。依据文件路径归属动态推断工作目录（根目录 vs 微服务子目录）。
*   **红蓝对抗验证 (Adversarial Validation)**
    *   **RedValidator**: 负责构造 Payload，尝试寻找利用攻击链的可能途径。Prompt 内置 13 类 vuln_type 的 PoC 构造提示。
        **逐参数判定强约束**：sink 多参数时只要任一参数仍可控就构成 EXPLOITABLE，单参数白名单不构成整体防御（防 LLM 浅推理误判 NOT_EXPLOITABLE）。NOT_EXPLOITABLE 时**强制带 `defense_analysis` 字段**（minLength: 20）证明每个参数都被过滤。
    *   **BlueValidator**: 负责审查代码库中的过滤器、拦截器或业务后置熔断机制。Prompt 路径 B 用于 fast-path 静态定性，含 7 类允许的 DEFENDED 证据 + 5 类禁用理由。
        **教学项目强约束**：禁止以"代码来自教学/演示/CTF/靶场（WebGoat / DVWA / Juice Shop / SecurityShepherd / Vulhub / OWASP Benchmark）"作为 DEFENDED 理由，教学项目代码就是真漏洞代码，按生产代码同等严格判定。
    *   **ConfigValidator**: 从 BlueValidator 拆分出的独立 Agent，专门处理 **14 种 taint_required=false 的静态配置漏洞**（弱加密、弱随机、硬编码凭据、不安全 TLS、JWT None、不安全 Cookie、信任边界违反等），走 fast-path 直接静态定性，跳过 ReverseTracer+RedValidator。
    *   通过左右互搏，系统能最大程度消除传统 SAST 工具的**高误报率**。
*   **vuln_type 全链路强制规范化**
    *   `vuln_type` 是漏洞聚合 / CWE 映射 / 报告分类的唯一 key。
    *   `state_router._build_merged_payload` 在每次跨 Agent merge 时把 `vuln_type` 强制还原到上游权威值（`sink_details.vuln_class`），即使 LLM 偶发写成 "CWE-918: ..." 或 "服务端请求伪造" 也会被自动覆盖。
*   **动态 Prompt 模板加载 (Dynamic Prompt Templates)**
    *   所有智能体 Prompt 存储于 `prompts/core/` 目录下的 YAML 文件中，同时携带 `output_schema`。
    *   引擎按 Agent 名加载模板，只做 `{payload_json}` 一处变量替换；追踪策略由大模型自行识别。
*   **Semgrep 静态扫描集成 (Semgrep Integration)**
    *   支持自定义 Semgrep 规则目录或单文件规则（指定自定义规则时不加载内置规则，否则使用内置规则）。
    *   一次性扫描产出 `routes`（API 路由）和 `sinks`（危险点）两类结构化结果。
    *   **入口 sink/route 自动去重**：sink 按 `(vuln_class, filepath, line)`，route 按 `(method, path, handler_file)`。
    *   引擎启动时立即触发，按 `taint_required` 元数据分流派发。
    *   **全局 `--exclude` 14 条 glob** 排除 test/it/mitigation/build/target/wrapper/playwright 等非业务目录，避免测试代码/教学反例被审计。
    *   **Pattern-not 精确化**：v13 起列举多 arity 全字面量代替 `"...", ...` 通配，避免漏检 `new ProcessBuilder("sh", "-c", userInput)` / `Paths.get("/safe", userInput)` 等"首字面量+后变量"形态。
*   **跨微服务追踪 (Cross-Service Tracing)**
    *   严格模式：只有**根目录无构建文件且子目录各自有 `pom.xml` / `build.gradle` / `package.json` / `go.mod` 等**才识别为多微服务；否则按单项目处理。避免 BenchmarkJava 这类单项目下的 `scorecard / results / VMs` 等普通子目录被误识别。
    *   支持 ReverseTracer 发出跨微服务追踪请求（场景 B），引擎自动在所有微服务中并发启动溯源 Agent。
    *   echo 污染检测：LLM 输出 `action=cross_service_trace` 但同时含 `call_chain` / `entry_route` 时清洗场景 B 字段后按场景 A 派发，避免 fan-out 风暴。
*   **Web 实时看板 (Real-time Web Dashboard)**
    *   内置 HTTP 服务器（默认端口 8080），提供 Vue.js 驱动的实时监控看板。
    *   显示审计进度、Token 消耗、漏洞统计、Agent 状态、红蓝对抗看板。
    *   支持查看每个 Agent 的会话详情、消息历史、工具调用记录。
    *   漏洞数据从**被审计项目目录**的 `reports/` 读取（修复了之前从 CodeAudit 项目读取的 bug）。
*   **报告生成 (Report Generation)**
    *   每个 VULNERABLE 漏洞由 **BlueValidator/ConfigValidator 直接生成 Markdown 报告**，写入 `<target_dir>/reports/vuln/{vuln_type}_{task_id}.md`。
    *   Markdown 报告内容：CWE、严重度、入口路由、文件路径、调用链、漏洞描述、攻击向量、PoC、最大影响。**不需要修复建议**。
    *   引擎收尾自动生成 `<target_dir>/reports/SUMMARY.md`：按严重度排序的全量汇总（含按类型 / 按文件 Top10 / 失败任务统计），并引用各独立 MD 报告。

## 🏗️ 智能体架构 (Agent Roster)

> 自 v6.1 起，原 Coordinator 节点已下线 —— 其"项目测绘 / 路由提取"职责由 Semgrep 规则直接承担，引擎通过 `_discover_microservices()` 直接扫描子目录识别微服务。
>
> 自 v7.x 起，**ReportGenerator 节点已下线** —— 改为 `state_router._build_report_fields()` 纯 Python 字段映射 + CWE / severity 查表，省一次 LLM 调用。
>
> 自 v8.x 起，**ConfigValidator 从 BlueValidator 拆分** —— 专门处理 taint_required=false 的 14 种静态配置漏洞。

| 角色名称 | 类型 | 职责说明 | 工具权限 |
| :--- | :--- | :--- | :--- |
| **SemgrepScanner** | 静态扫描器 | 使用内置 + 用户规则扫描，一次性产出 API 路由（`routes`）和危险点（`sinks`）；全局 14 条 `--exclude` 排除测试/教学反例 | 无（外部进程）|
| **ReverseTracer** | 专家节点 | 接收 Sink 坐标，自底向上逆向追踪调用链，支持跨微服务追踪。场景 C（追踪断裂）输出 `status: NOT_EXPLOITABLE` + `break_reason`（≥20 字符） | `lsp, read, codesearch` + CodeGraph MCP（强制用 codegraph 读取代码） |
| **LogicAuditor** | 专家节点 | 从 API 路由向下正向推演业务逻辑漏洞（IDOR、Privilege Escalation、Authentication Bypass、Open Redirect），输出限定 **4 类标准 vuln_type 白名单**；遇到技术类漏洞（SQL Injection 等）强制返回 DEFENDED 让位 Sink 路径；timeout=480s（其他 agent 300s） | `lsp, read, codesearch` + CodeGraph MCP |
| **RedValidator** | 攻击验证节点 | 扮演红队构造 Payload，验证漏洞可利用性，生成攻击向量；**逐参数判定 exploitability**，NOT_EXPLOITABLE 时强制带 defense_analysis（minLength: 20）证明 | `lsp, read, codesearch` + CodeGraph MCP |
| **BlueValidator** | 防御验证节点 | 扮演蓝队核查防御机制（过滤器、拦截器），确认最终漏洞。**判定 VULNERABLE 时直接生成 Markdown 报告**。禁止以教学项目作为 DEFENDED 理由 | `lsp, read, codesearch` + CodeGraph MCP |
| **ConfigValidator** | 配置静态分析专家 | 从 BlueValidator 拆分，专门处理 **taint_required=false 的 14 种静态配置漏洞**（弱加密、弱随机、硬编码凭据、不安全 TLS、JWT None、不安全 Cookie、信任边界违反、敏感信息泄露等），**判定 VULNERABLE 时直接生成 Markdown 报告** | `lsp, read, codesearch` + CodeGraph MCP |
| **summary 汇总** | Python 函数 | `build_summary_report.build_summary()`：聚合 reports/vuln/ 下全部 MD 报告写 `reports/SUMMARY.md`。引擎收尾自动调用。 | — |

## 🚀 快速开始 (Quick Start)

### 依赖要求
- Python 3.10+
- `claude` CLI 工具（Claude Code）
- `semgrep`（用于扫描 API 路由和漏洞点）
- `codegraph`（代码智能增强，通过 MCP 提供代码结构查询）
- `aiohttp`, `PyYAML`, `jsonschema`, `claude-agent-sdk`

### 安装依赖
```bash
# 推荐：pyproject.toml 已加 entry point,装完后可用 `codeaudit` 命令
pip install -e .

# 安装 CodeGraph（代码智能增强，通过 MCP 提供代码结构查询）
# macOS / Linux
curl -fsSL https://raw.githubusercontent.com/colbymchenry/codegraph/main/install.sh | sh
# Windows (PowerShell)
irm https://raw.githubusercontent.com/colbymchenry/codegraph/main/install.ps1 | iex

# 或手动装最小依赖
pip install aiohttp pyyaml semgrep jsonschema claude-agent-sdk
```

### 启动引擎
```bash
# 装完后直接用 codeaudit CLI（pyproject.toml entry point）
codeaudit /path/to/your-java-project

# 或仍用 module 方式
python3 -m src.main /path/to/your-java-project
```

### 高级选项
```bash
# 使用自定义 Semgrep 规则（目录或单文件）—— 此时不会加载内置规则
codeaudit /path/to/proj --semgrep-rules /your/rules/

# 单独生成已有 reports/ 的汇总（不重新扫描）
python3 -m src.build_summary_report --target-dir /path/to/proj
```

引擎启动后，会自动：
1. 清理目标目录下的旧 `.a2a_bus/`、`.a2a_logs/`、`reports/`
2. 在目标目录下重建 `.a2a_bus/` 消息总线目录
3. 启动 Web 看板（默认端口 8080）
4. 开始审计流程：
   - 通过 `_discover_microservices()` 严格识别微服务（要求构建文件存在），按服务数自动扩容沙盒池
   - Semgrep 一次性扫描 API 路由（`routes`）和漏洞点（`sinks`），按 `(vuln_class, filepath, line)` 去重
   - 并发派发：
     - 每条 route → LogicAuditor → RedValidator → BlueValidator → Python 落盘
     - 每个 sink 按 `taint_required` 分流：
       - `true`（默认，注入类/反序列化/SSRF/XXE/JNDI/Code Injection 等）→ ReverseTracer → RedValidator → BlueValidator → Python 落盘（4 跳）
       - `false`（弱加密/弱随机/硬编码/Insecure TLS/JWT None/Insecure Cookie 等"sink 即漏洞"）→ **ConfigValidator** fast path → Python 落盘（2 跳）
5. **全部任务处理完毕后自然退出**（主循环追踪 in-flight 协程，连续 2 轮空闲即收尾），无需 Ctrl+C
6. 退出时自动产出 `reports/SUMMARY.md` 汇总报告

### 目录结构
```
CodeAudit/
├── src/                            # 核心引擎代码
│   ├── main.py                     # CLI 入口
│   ├── engine.py                   # 异步调度引擎（主循环 + 跨服务接力 + in-flight 追踪 + 收尾汇总）
│   ├── claude_agent.py             # Claude Agent SDK 客户端
│   ├── claude_manager.py           # Claude Agent 会话管理器
│   ├── a2a_bus.py                  # 文件系统消息总线（tmp+fsync+rename 原子写）
│   ├── state_router.py             # 数据驱动路由（ROUTE_RULES + vuln_type 规范化 + Python 报告映射）
│   ├── state_tracker.py            # Web 前端状态追踪 + session 轮询
│   ├── semgrep_scanner.py          # Semgrep 静态扫描器
│   ├── prompts.py                  # Prompt + output_schema 加载器
│   └── build_summary_report.py     # 漏洞汇总 markdown 生成器（无 LLM）
├── prompts/                        # 智能体 Prompt 模板库
│   └── core/                       # 每份含 system_prompt_template + output_schema
│       ├── reverse_tracer.yaml     # 污点追踪专家（场景 C 输出 break_reason）
│       ├── logic_auditor.yaml      # 业务逻辑审计
│       ├── red_validator.yaml      # 红队攻击验证
│       ├── blue_validator.yaml     # 蓝队防御验证
│       ├── config_validator.yaml   # 配置静态分析（taint_required=false 专用）
│       ├── cross_service_prefilter.yaml
│       └── retry.yaml
├── semgrep_rules/                  # Semgrep 规则集合（~180 条 rule_id / 83 yaml，覆盖 Java/Python/C/C++）
│   └── custom/
│       ├── java/                   # 34 yaml — 规则 id 带 java- 前缀
│       │   ├── spring-api.yaml     # Spring API 路由提取（非漏洞，12 条 rule）
│       │   #  走完整污点链 (taint_required: true)
│       │   ├── sql-injection.yaml      # JDBC/JdbcTemplate/Hibernate/JPA/MyBatis 注解 + R2DBC + 链式 (5 rules)
│       │   ├── mybatis-xml-sql-injection.yaml
│       │   ├── command-injection.yaml  # Runtime/ProcessBuilder/Desktop/Commons Exec/JSch
│       │   ├── code-injection.yaml     # OGNL/MVEL/Groovy/JEXL/ScriptEngine
│       │   ├── path-traversal.yaml     # File/FileChannel/Paths/Path.of/Hadoop HDFS/Spring Resource/JSch SFTP/Apache VFS/Commons IO/Guava + SafeText 过滤排除
│       │   ├── zip-slip.yaml           # ZipEntry/TarArchiveEntry
│       │   ├── nosql-injection.yaml    # MongoDB/Cassandra/Neo4j/ElasticSearch
│       │   ├── ldap-injection.yaml
│       │   ├── xpath-injection.yaml
│       │   ├── template-injection.yaml # Velocity/FreeMarker/Pebble/Thymeleaf/Mustache/StringSubstitutor
│       │   ├── spel-injection.yaml
│       │   ├── xxe.yaml                # DOM/SAX-StAX/Transform-Validate 拆 3 id
│       │   ├── ssrf.yaml               # 拆 execution (HIGH) / construction (LOW + taint) 2 id
│       │   ├── unsafe-deserialization.yaml  # ObjectInputStream/XStream/SnakeYAML/XMLDecoder/Jackson/Kryo/Hessian/FastJson
│       │   ├── unsafe-reflection.yaml  # Class.forName/loadClass/Method.invoke/Field/Unsafe
│       │   ├── unsafe-dynamic-class-loading.yaml
│       │   ├── jndi-injection.yaml
│       │   ├── jdbc-url-tainted.yaml   # MySQL/H2/Postgres 协议级 RCE 入口
│       │   ├── xss.yaml                # PrintWriter/ServletOutputStream/Model.addAttribute/ResponseEntity.body
│       │   ├── open-redirect.yaml
│       │   ├── unvalidated-forward.yaml  # RequestDispatcher.forward/include
│       │   #  无须污点链 (taint_required: false) — 走 fast path 到 ConfigValidator
│       │   ├── weak-cryptography.yaml  # 弱算法/Mac/Signature/EC 短曲线/BC 弱密码/XOR 自定义
│       │   ├── weak-random.yaml
│       │   ├── insecure-crypto-config.yaml  # Static IV / Constant Salt / Insufficient Key Size (3 rules)
│       │   ├── hardcoded-credentials.yaml
│       │   ├── insecure-trust-manager.yaml  # 空 TrustManager / 恒真 HostnameVerifier / Allow-All / TrustAllStrategy
│       │   ├── jwt-none.yaml           # auth0 Algorithm.none / jjwt parseClaimsJwt / Nimbus PlainJWT
│       │   ├── insecure-cookie.yaml    # 显式 false / 缺失 setSecure (2 rules)
│       │   ├── trust-boundary.yaml     # session.setAttribute 非字面量
│       │   ├── insecure-temp-file.yaml
│       │   ├── stack-trace-exposure.yaml
│       │   ├── sensitive-data-in-log.yaml  # 关键字命中 + 容器对象启发式 (2 rules)
│       │   └── sensitive-data-in-url.yaml
│       ├── python/                 # 28 yaml — 规则 id 带 python- 前缀
│       │   #  走完整污点链 (taint_required: true)
│       │   ├── sql-injection.yaml      # DB-API cursor.execute / SQLAlchemy text/exec / 字符串拼接
│       │   ├── command-injection.yaml  # os.system/popen + subprocess(shell=True) + pexpect
│       │   ├── code-injection.yaml     # eval/exec/compile + importlib 动态导入
│       │   ├── path-traversal.yaml     # open/os.* /shutil.* / pathlib + Zip Slip
│       │   ├── ssrf.yaml               # requests/httpx/urllib/aiohttp
│       │   ├── xxe.yaml                # xml.etree/lxml/sax/minidom + defusedxml 排除
│       │   ├── unsafe-deserialization.yaml  # pickle/cPickle/yaml.load/marshal/jsonpickle
│       │   ├── template-injection.yaml # Jinja2/Mako/Django SSTI
│       │   ├── xss.yaml                # Markup/mark_safe/HttpResponse 裸写
│       │   ├── open-redirect.yaml      # Flask/Django redirect / HttpResponseRedirect
│       │   ├── ldap-injection.yaml     # python-ldap/ldap3 search_s filter
│       │   ├── xpath-injection.yaml    # lxml xpath / ElementTree find
│       │   ├── nosql-injection.yaml    # MongoDB $where/eval + Redis EVAL Lua
│       │   #  无须污点链 (taint_required: false)
│       │   ├── weak-cryptography.yaml  # hashlib MD5/SHA1 + pycryptodome DES/RC4/Blowfish/ECB + 硬编码密钥
│       │   ├── weak-random.yaml        # random.* (非 secrets/SystemRandom)
│       │   ├── hardcoded-credentials.yaml  # password/secret/token 字面量赋值
│       │   ├── insecure-temp-file.yaml # tempfile.mktemp + /tmp 固定路径
│       │   ├── sensitive-data-in-log.yaml  # logging/print 含敏感关键字
│       │   ├── stack-trace-exposure.yaml    # traceback.format_exc 返回响应
│       │   ├── insecure-cookie.yaml    # Flask/Django set_cookie(secure=False) + 缺失 secure
│       │   ├── jwt-none.yaml           # PyJWT algorithms=['none'] / verify=False
│       │   ├── insecure-tls.yaml       # requests verify=False / ssl._create_unverified_context
│       │   ├── insecure-crypto-config.yaml  # 静态 IV / 常量 Salt / 密钥长度不足
│       │   ├── sensitive-data-in-url.yaml  # logging 记录 request.url/query_string
│       │   ├── trust-boundary.yaml     # session[key] = request.args[key] 信任边界写入
│       │   #  路由提取（非漏洞）
│       │   ├── flask-api.yaml           # Flask @app.route / @app.get/post/put/delete
│       │   ├── fastapi-api.yaml         # FastAPI @app.get/post + APIRouter
│       │   └── django-api.yaml          # Django path/re_path + DRF @api_view
│       └── cpp/                    # 21 yaml — 规则 id 带 cpp- 前缀
│           #  走完整污点链 (taint_required: true)
│           ├── command-injection.yaml     # system/popen/exec* + Windows CreateProcess
│           ├── path-traversal.yaml        # fopen/open/stat/unlink/CreateFile + cpp17 filesystem
│           ├── sql-injection.yaml         # mysql_query/PQexec/sqlite3_exec/ODBC/OCI
│           ├── xxe.yaml                   # libxml2/pugixml/tinyxml
│           ├── ssrf.yaml                  # libcurl CURLOPT_URL 接收非字面量
│           ├── ldap-injection.yaml        # OpenLDAP ldap_search_ext_s filter
│           ├── xpath-injection.yaml       # libxml2 xmlXPathEvalExpression
│           ├── zip-slip.yaml              # minizip entry name 拼路径
│           ├── code-injection.yaml        # dlopen/LoadLibrary 接收非字面量路径
│           ├── open-redirect.yaml         # Crow/cpphttplib redirect + Location header
│           ├── unbounded-memcpy.yaml      # memcpy/memmove/memset 长度参数污点
│           #  无须污点链 (taint_required: false)
│           ├── buffer-overflow.yaml       # strcpy/strcat/gets/sprintf/scanf 无边界
│           ├── format-string.yaml         # printf/fprintf/sprintf/syslog 非字面量 fmt
│           ├── weak-cryptography.yaml     # OpenSSL MD5/SHA1/DES/RC4/ECB + 硬编码密钥
│           ├── hardcoded-credentials.yaml # std::string password = "..."
│           ├── weak-random.yaml           # rand()/random()/srand()
│           ├── sensitive-data-in-log.yaml # printf/syslog/cout 含敏感关键字
│           ├── insecure-tls.yaml          # SSL_VERIFY_NONE + 弱密码套件
│           ├── insecure-crypto-config.yaml  # 静态 IV / 常量 Salt
│           ├── insecure-temp-file.yaml    # tmpnam/mktemp + 固定 /tmp 路径
│           └── memory-safety.yaml         # 整数溢出/UAF/Double Free/Null Deref/OOB/Off-by-One/未初始化/TOCTOU
├── skill/                          # Claude Code skill 形态（按角色独立分发）
│   ├── reverse-tracer/             # 强制用 codegraph 读取代码
│   ├── logic-auditor/
│   ├── red-validator/
│   ├── blue-validator/
│   └── config-validator/           # taint_required=false 专用
├── web/                            # Web 前端界面
│   └── index.html                  # Vue.js 实时看板
├── doc/                            # 详细设计文档
└── reports/                        # 漏洞报告输出目录（自动生成）
    ├── vuln/                       # 每个 VULNERABLE 的独立 Markdown 报告
    │   └── {vuln-type}_{task-id}.md
    └── SUMMARY.md                  # 汇总报告（引擎收尾自动产出）
```

## 🔧 配置说明

### ClaudeAgentManager 配置

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `max_active` | 最大并发 Agent 数；引擎启动时会按微服务数自动上调至 `max(5, 服务数)` | 5 |
| `default_timeout` | 默认超时时间(秒) | 1800 |

### 引擎配置

| 常量 | 说明 | 默认值 |
|------|------|--------|
| `MAX_CONCURRENT_AGENTS` | 初始 Semgrep 派发任务的并发上限（主 semaphore） | 5 |
| `MAX_CHAIN_AGENTS` | 链路续接（Reverse→Red→Blue 等）的专用并发上限（chain semaphore），避免被初始批量派发挤入 FIFO 队列饿死 | 3 |
| `MAX_AGENT_TIMEOUT` | 单次 Claude Agent 调用超时(秒，默认值) | 300 |
| `PER_AGENT_TIMEOUT` | 个别 Agent 的超时覆盖表（如 `LogicAuditor: 480`，跨文件追读耗时长） | `{"LogicAuditor": 480}` |
| `MAX_TIMEOUT_RETRIES` | 单任务超时后的重试次数（救偶发 provider 抖动） | 1 |

### 环境变量

| 变量 | 说明 |
|------|------|
| `CLAUDE_CODE_CLI_PATH` | Claude Code CLI 路径（默认 claude） |

## 📦 Skill 形态（轻量分发）

`skill/security-audit-java/` 提供同款规则 + 方法论的 **Claude Code skill 封装**，
不依赖 Claude Agent SDK 和 Python 多 Agent 引擎，**在用户当前会话内单进程跑通**：

```bash
cd skill/security-audit-java
./install.sh                    # 装到 ~/.claude/skills/（Claude Code 全局）
./install.sh --project          # 装到 ./.claude/skills/（项目级）
```

之后在 Claude Code 里以自然语言（"审计这个 Java 项目"）触发。

差异：skill 把多 Agent 流水线压缩为单 session 的 6 阶段工作流，丢了 Red/Blue 对抗的隔离性，但换来零环境依赖。规则 + DEFENDED 证据规范 + PoC 提示是同一套。

**三层防偷懒机制**（解决"LLM 拿到 30+ 条 Semgrep result 不逐条裁决"问题）：

1. **`scripts/dispatch.py` 脚本去噪**：去重 + 路由发现规则过滤（vuln_class 为空丢弃）+ `taint_required: false` fast-path 自动�� finding（无须 LLM）。WebGoat 实测让 LLM 实际处理任务 237 → 88，减 63%。
2. **TodoList 强制驱动**：阶段 2 强制对每条 pending finding 调 `TaskCreate`，阶段 3 严格按 `in_progress → 裁决 → completed` 单条循环，阶段 4 `TaskList` 自检 `pending == 0` 才能进收尾。
3. **`reference/` 文档强制深度分析**：13 份按家族分组的 .md 覆盖 39 个 vuln_type，每份含 6 段标准结构（sink 模式 / 数据流追溯 / 防御机制速查 / 常见误判 / 证据引用范例 / PoC 模板），内嵌 v11/v12/v13 baseline 实测的反面教材作为反例。

## 📖 详细技术报告

完整的工程演进与教训沉淀见 **[REPORT.md](REPORT.md)**（5 万字）——
基于 6 轮 WebGoat baseline 迭代（v8 → v13）的实战记录，含：

- 4 组深度 Case Study（Schema 陷阱 / LLM 浅推理 / Semgrep pattern-not 陷阱 / LLM 不逐条分析）
- v8 → v13 完整数据：总 VULN 122→133、严格 Precision 78%→84%、Lesson 召回 83%→96%、失败率 3.6%→0%、耗时 1h13→50min
- 评估方法学（多维度 Precision/Recall + 6 步验证流水线）
- 可迁移到任意 LLM-工程项目的经验沉淀

## 📚 详细设计文档

更详细的架构设计、调度逻辑和 A2A 通信协议请参考以下文档（位于 `doc/` 目录下）：

- [概要设计](doc/概要设计)
- [多智能体调度引擎与状态机详细设计](doc/多智能体调度引擎与状态机详细设计文档)
- [核心智能体提示词工程规范](doc/核心智能体提示词工程规范详细设计文档)
- [A2A 通信 JSON Schema 详细设计](doc/A2A%20通信%20JSON%20Schema%20详细设计)

## 📡 Claude Agent SDK 交互

系统通过 `claude-agent-sdk` 包调用本地 Claude Code CLI，主要使用：

- `query()` - 一次性查询，返回消息流
- `ClaudeAgentOptions` - 配置工具列表、工作目录、超时等
- `permission_mode` - 控制工具执行权限（acceptEdits 自动接受文件编辑）

**超时与重试机制**：

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `max_turns` | 最大对话轮次（None=无限制） | None |
| `max_budget_usd` | 最大预算美元（None=无限制） | None |
| `timeout` (hook) | 单个 hook 超时，默认 60 秒 | 60s |
| `load_timeout_ms` | session_store.load() 超时 | 60000ms |
| `initialize_timeout` | 初始化请求超时 | 60s |

**注意**：SDK 本身没有 schema 验证失败重试机制。如果模型输出不符合 schema，SDK 返回 `structured_output=None`，由业务层（CodeAudit 引擎）处理降级提取。

更多 API 详情请参考 [Claude Agent SDK 文档](https://code.claude.com/docs/zh-CN/agent-sdk/overview)。