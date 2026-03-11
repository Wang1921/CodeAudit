# CodeAudit - 双轨制多智能体代码审计系统 (Multi-Agent Code Auditing System)

CodeAudit 是一个**高度自动化、具备专家级推理能力**的代码审计引擎。系统通过 **Python 异步引擎** 驱动，结合 **OpenCode HTTP 沙盒池** 和 **Semgrep 静态扫描器**，利用多个具有特定安全专业领域的大模型智能体 (Agents) 进行协同作战。

系统采用独特的**双轨制（自底向上与自顶向下并行）**架构，通过 **A2A 文件系统消息总线** 实现 Agent 间通信，能够发现技术型漏洞（如 SQL 注入、路径遍历）和业务逻辑漏洞（如 IDOR 越权、条件竞争）。

## 🌟 核心特性 (Core Features)

*   **双轨并行审查 (Dual-Track Auditing)**
    *   **技术轨道 (Bottom-Up)**: 通过 Semgrep 静态扫描器发现底层危险函数 (Sinks)，向上逆向追踪，专攻 CWE-22（路径遍历）、CWE-73（文件外部控制）及各类注入漏洞。
    *   **业务轨道 (Top-Down)**: 从 API 路由入口向下正向推演，专攻 IDOR（越权）、并发等状态机逻辑漏洞。
*   **文件系统即总线 (A2A over File System IPC)**
    *   采用本地文件系统目录（`.a2a_bus/`）作为异步消息总线。
    *   Agent 之间通过读写强类型的 JSON 信封 (TaskRequest / TaskResult) 进行任务流转，具备极强的可观测性和容错性。
*   **HTTP 沙盒池 (HTTP Sandbox Pool)**
    *   Python 引擎管理多个 OpenCode 服务器实例，采用 LRU 缓存策略（默认最大 5 个并发）。
    *   自动健康检查 (`/global/health`)，失败时自动重启。
    *   达到并发上限时自动回收最旧的沙盒服务器。
*   **动态工具权限分配 (Dynamic Tool Permissions)**
    *   **Coordinator**: 拥有 `codesearch, glob, grep, read` 权限，用于全局项目测绘。
    *   **其他 Agent**: 拥有 `lsp, read, codesearch` 权限，开启重型武器 LSP 进行代码跳转。
    *   动态推断每个 Agent 的工作目录（根目录 vs 微服务子目录）。
*   **红蓝对抗验证 (Adversarial Validation)**
    *   **RedValidator**: 负责构造 Payload，尝试寻找利用攻击链的可能途径。
    *   **BlueValidator**: 负责审查代码库中的过滤器、拦截器或业务后置熔断机制。
    *   通过左右互搏，系统能最大程度消除传统 SAST 工具的**高误报率**。
*   **动态 Prompt 模板加载 (Dynamic Prompt Templates)**
    *   所有智能体 Prompt 存储于 `prompts/core/` 目录下的 YAML 文件中。
    *   引擎根据 Agent 类型动态加载对应的模板，支持变量替换（如 `{payload_json}`, `{dynamic_tracing_strategy}`）。
*   **Semgrep 静态扫描集成 (Semgrep Integration)**
    *   支持自定义 Semgrep 规则目录或单文件规则。
    *   自动将 Semgrep 输出转换为标准的 `sink_details` 格式。
    *   在 Coordinator 完成后自动触发，为每个发现的漏洞点生成 ReverseTracer 任务。
*   **跨微服务追踪 (Cross-Service Tracing)**
    *   自动识别项目中的微服务结构（通过 `pom.xml`, `package.json` 等构建文件）。
    *   支持 ReverseTracer 发出跨微服务追踪请求，引擎自动在所有微服务中并发启动溯源 Agent。
    *   构建全局服务路由表，支持跨服务调用链追踪。
*   **Web 实时看板 (Real-time Web Dashboard)**
    *   内置 HTTP 服务器（端口 8080），提供 Vue.js 驱动的实时监控看板。
    *   显示审计进度、Token 消耗、漏洞统计、Agent 状态、红蓝对抗看板。
    *   支持查看每个 Agent 的会话详情、消息历史、工具调用记录。

## 🏗️ 智能体架构 (Agent Roster)

| 角色名称 | 类型 | 职责说明 | 工具权限 |
| :--- | :--- | :--- | :--- |
| **Coordinator** | 调度器 | 扫描项目结构、识别微服务、提取 API 路由表，生成动态追踪策略 | `codesearch, glob, grep, read` |
| **SemgrepScanner** | 静态扫描器 | 使用 Semgrep 规则扫描代码库，发现底层危险函数（Sinks）| 无（外部进程）|
| **ReverseTracer** | 专家节点 | 接收 Sink 坐标，自底向上逆向追踪调用链，支持跨微服务追踪 | `lsp, read, codesearch` |
| **LogicAuditor** | 专家节点 | 从 API 路由向下正向推演业务逻辑漏洞（IDOR、条件竞争等）| `lsp, read, codesearch` |
| **RedValidator** | 攻击验证节点 | 扮演红队构造 Payload，验证漏洞可利用性，生成攻击向量 | `lsp, read, codesearch` |
| **BlueValidator** | 防御验证节点 | 扮演蓝队核查防御机制（过滤器、拦截器），确认最终漏洞 | `lsp, read, codesearch` |
| **ReportGenerator** | 报告节点 | 生成最终审计报告，保存 JSON 格式漏洞报告到 `reports/` 目录 | `lsp, read, codesearch` |
| **RetryAgent** | 重试节点 | 当 Agent 输出 JSON 格式错误时，自动触发重试修复 | `lsp, read, codesearch` |

## 🚀 快速开始 (Quick Start)

### 依赖要求
- Python 3.10+
- `opencode` CLI 工具链
- `semgrep` (用于扫描 API 路由和漏洞点）
- `aiohttp`, `PyYAML`

### 安装依赖
```bash
pip install aiohttp pyyaml
```

### 启动引擎
系统核心调度由 Python 异步引擎驱动，通过挂载目标项目根目录启动：

```bash
# 启动审计引擎，指定待审计的项目根目录
python -m src.main ./dummy_project
```

### 高级选项
```bash
# 使用自定义 Semgrep 规则（目录或单文件）
python -m src.main ./dummy_project --semgrep-rules ./semgrep_rules/
```

引擎启动后，会自动：
1. 在目标目录下创建 `.a2a_bus/` 消息总线目录
2. 在目标目录下创建 `.a2a_logs/` 日志目录
3. 在项目根目录下创建 `reports/` 漏洞报告目录
4. 启动 Web 看板（默认端口 8080）
5. 开始审计流程：
   - Coordinator 识别技术栈和微服务结构
   - Semgrep 一次性扫描 API 路由和漏洞点
   - 并发执行逆向追踪和逻辑审计

### 目录结构
```
CodeAudit/
├── src/                    # 核心引擎代码
│   ├── engine.py           # 异步调度引擎 (333 行）
│   ├── agent.py            # OpenCode HTTP 客户端 (227 行)
│   ├── server_manager.py   # HTTP 沙盒池管理器 (184 行)
│   ├── a2a_bus.py          # 文件系统消息总线 (112 行)
│   ├── state_router.py     # 状态路由与任务裂变 (320 行)
│   ├── state_tracker.py    # Web 前端状态追踪 (327 行)
│   ├── semgrep_scanner.py  # Semgrep 静态扫描器 (205 行)
│   └── prompts.py          # 动态模板加载器 (50 行)
├── prompts/                # 智能体 Prompt 模板库
│   ├── core/               # 核心智能体模板
│   │   ├── coordinator.yaml
│   │   ├── reverse_tracer.yaml
│   │   ├── logic_auditor.yaml
│   │   ├── red_validator.yaml
│   │   ├── blue_validator.yaml
│   │   ├── report_generator.yaml
│   │   └── retry.yaml
│   └── hunters.yaml        # 语言分层猎手配置
├── semgrep_rules/          # Semgrep 规则集合
│   └── custom/
│       └── spring-api.yaml
├── web/                    # Web 前端界面
│   └── index.html          # Vue.js 实时看板 (449 行)
├── doc/                    # 详细设计文档
├── reports/                # 漏洞报告输出目录（自动生成）
└── dummy_project/          # 测试项目（多微服务架构）
```

## 🔧 配置说明

### OpenCodeServerManager 配置

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `max_active_servers` | 最大并发沙盒数 | 5 |
| `hostname` | 监听主机名 | 127.0.0.1 |
| `cors_origins` | CORS 允许的来源列表 | [] |
| `health_check_timeout` | 健康检查超时(秒) | 30.0 |
| `health_check_interval` | 健康检查重试间隔(秒) | 0.5 |

### 环境变量

| 变量 | 说明 |
|------|------|
| `OPENCODE_SERVER_PASSWORD` | 启用 HTTP Basic 认证 |
| `OPENCODE_SERVER_USERNAME` | 认证用户名（默认 opencode） |

## 📚 详细设计文档

更详细的架构设计、调度逻辑和 A2A 通信协议请参考以下文档（位于 `doc/` 目录下）：

- [概要设计](doc/概要设计)
- [多智能体调度引擎与状态机详细设计](doc/多智能体调度引擎与状态机详细设计文档)
- [核心智能体提示词工程规范](doc/核心智能体提示词工程规范详细设计文档)
- [A2A 通信 JSON Schema 详细设计](doc/A2A%20通信%20JSON%20Schema%20详细设计)

## 📡 OpenCode API 交互

系统通过 HTTP API 与 opencode 服务器交互，主要端点包括：

- `GET /global/health` - 健康检查
- `POST /session` - 创建会话
- `POST /session/:id/message` - 发送消息
- `DELETE /session/:id` - 删除会话
- `GET /session/:id/diff` - 获取代码差异

更多 API 详情请参考 opencode 官方文档。
