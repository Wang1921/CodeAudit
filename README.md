# CodeAudit - 双轨制多智能体代码审计系统 (Multi-Agent Code Auditing System)

CodeAudit 是一个**高度自动化、具备专家级推理能力**的代码审计引擎。系统集成了 `opencode` CLI 沙盒环境，并结合 **Google A2A (Agent-to-Agent) 协议理念**，利用多个具有特定安全专业领域的大模型智能体 (Agents) 进行协同作战。

通过独特的**双轨制（自底向上与自顶向下并行）**架构，系统不仅能够发现传统静态分析工具擅长的技术型漏洞（如 SQL 注入、路径遍历），更能深入理解业务上下文，挖掘复杂的**业务逻辑漏洞**（如 IDOR 越权、条件竞争）。

## 🌟 核心特性 (Core Features)

*   **双轨并行审查 (Dual-Track Auditing)**
    *   **技术轨道 (Bottom-Up)**: 从底层危险函数 (Sinks) 向上逆向追踪，专攻 CWE-22（路径遍历）、CWE-73（文件外部控制）及各类注入漏洞。
    *   **业务轨道 (Top-Down)**: 从 API 路由入口向下正向推演，专攻 IDOR（越权）、并发等状态机逻辑漏洞。
*   **文件系统即总线 (A2A over File System IPC)**
    *   采用本地文件系统目录（`.a2a_bus/`）作为异步消息总线。
    *   Agent 之间通过读写强类型的 JSON 信封 (TaskRequest / TaskResult) 进行任务流转，具备极强的可观测性和容错性。
*   **无头沙盒执行 (Headless Sandbox Execution)**
    *   每个 Agent 作为一个独立的 `opencode` CLI 进程运行，按需被分配读取权限。
    *   Agent 可以自主编写探测脚本、调用原生 LSP (语言服务器协议) 动态提取和跳转代码片段。
*   **红蓝对抗验证 (Adversarial Validation)**
    *   **红队 (RedValidator)**: 负责构造 Payload，尝试寻找利用攻击链的可能途径。
    *   **蓝队 (BlueValidator)**: 负责审查代码库中的过滤器、拦截器或业务后置熔断机制。
    *   通过左右互搏，系统能最大程度消除传统 SAST 工具的**高误报率**。
*   **动态模板加载 (Dynamic Prompt Templates)**
    *   所有智能体 Prompt 不再硬编码在代码中，而是存储于 `prompts/` 目录下的 YAML 文件中。
    *   引擎根据识别的语言栈动态加载对应的猎手模板。
*   **语言分层猎手矩阵 (Language-Specific Hunter Matrix)**
    *   针对不同编程语言维护独立的漏洞猎手，实现领域对焦最大化。
    *   Java 猎手专注 JDBC/MyBatis/SpEL，Python 猎手专注 SQLAlchemy/os.system。
*   **强制安全红线 (Mandatory Security Baseline)**
    *   引擎在任务裂变时强制注入通用底线猎手（Secret_Hunter, Privacy_Hunter）。
    *   确保所有识别的 API 路由 100% 覆盖 LogicAuditor 审查。

## 🏗️ 智能体架构 (Agent Roster)

| 角色名称 | 类型 | 职责说明 |
| :--- | :--- | :--- |
| **Coordinator** | 调度器 | 负责扫描项目结构与语言栈，提取 API 路由表，生成动态追踪策略 |
| **SinkHunter (集群)** | 专家集群 | 基于 YAML 模板加载，专精某一语言的特定底层库，精准提取高危触点 |
| ┣ **FileIO_Hunter** | 实例化节点 | 专攻 CWE-22/73，路径遍历、文件解压炸弹 |
| ┣ **Injection_Hunter** | 实例化节点 | 专攻注入类 (JNDI, LDAP, OGNL, SpEL) |
| ┣ **DbQuery_Hunter** | 实例化节点 | 专攻 SQL/NoSQL 注入 |
| ┣ **Secret_Hunter** | 实例化节点 | 专攻 CWE-798 硬编码凭证 |
| ┣ **Privacy_Hunter** | 实例化节点 | 专攻 CWE-532 敏感日志 |
| **ReverseTracer** | 专家节点 | 接收 Sink 坐标，自底向上逆向追踪调用链 |
| **LogicAuditor** | 专家节点 | 从 API 路由向下正向推演业务逻辑漏洞 |
| **RedValidator** | 攻击验证节点 | 扮演红队构造 Payload，验证漏洞可利用性 |
| **BlueValidator** | 防御验证节点 | 扮演蓝队核查防御机制，确认最终漏洞 |

## 🚀 快速开始 (Quick Start)

### 依赖要求
- Python 3.10+
- `opencode` CLI 工具链
- PyYAML

### 安装依赖
```bash
pip install pyyaml
```

### 启动引擎
系统核心调度由 Python 实现的异步引擎驱动，通过挂载目标项目根目录作为工作区启动：

```bash
# 启动审计引擎，并指定待审计的项目根目录（如 dummy_project）
python -m src.main ./dummy_project
```

引擎启动后，会在目标目录下自动创建 `.a2a_bus/` 目录结构，并进入监听轮询模式。系统的运行日志将直接输出到控制台。

### 目录结构
```
CodeAudit/
├── src/                    # 核心引擎代码
│   ├── engine.py           # 异步调度引擎
│   ├── agent.py            # OpenCode 子进程管理
│   ├── a2a_bus.py          # 文件系统消息总线
│   ├── state_router.py     # 状态路由与任务裂变
│   └── prompts.py          # 动态模板加载器
├── prompts/                # 智能体 Prompt 模板库
│   ├── core/               # 核心智能体模板
│   │   ├── coordinator.yaml
│   │   ├── reverse_tracer.yaml
│   │   ├── logic_auditor.yaml
│   │   ├── red_validator.yaml
│   │   └── blue_validator.yaml
│   ├── hunters/            # 漏洞猎手模板
│   │   ├── java/           # Java 猎手
│   │   ├── python/         # Python 猎手
│   │   └── hunters.yaml    # 猎手注册表
│   └── core/retry.yaml     # JSON 契约修复模板
├── doc/                    # 设计文档
└── dummy_project/          # 测试项目
```

## 📚 详细设计文档

更详细的架构设计、调度逻辑和 A2A 通信协议请参考以下文档（位于 `doc/` 目录下）：

- [概要设计](doc/概要设计)
- [多智能体调度引擎与状态机详细设计](doc/多智能体调度引擎与状态机详细设计文档)
- [核心智能体提示词工程规范](doc/核心智能体提示词工程规范详细设计文档)
- [A2A 通信 JSON Schema 详细设计](doc/A2A%20通信%20JSON%20Schema%20详细设计)
