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

## 🏗️ 智能体架构 (Agent Roster)

1.  **调度器 (Coordinator)**: 扫描项目语言栈，提取路由表，点将派发具体的猎手任务。
2.  **底层猎手集群 (SinkHunters)**: 针对特定漏洞 (CWE) 检索源代码中的危险执行触点。
3.  **逆向溯源专家 (ReverseTracer)**: 接收底层猎手提供的漏洞坐标，通过控制流/数据流自底向上追踪调用链路。
4.  **业务逻辑推演专家 (LogicAuditor)**: 从 API 路由入口开始，自顶向下进行逻辑审计，审查鉴权模型和并发锁。
5.  **红队验证官 (RedValidator)**: 对疑似漏洞进行利用推演。
6.  **蓝队验证官 (BlueValidator)**: 对漏洞利用链路进行防御复盘，确认最终有效漏洞。

## 🚀 快速开始 (Quick Start)

### 依赖要求
- Python 3.10+
- `opencode` CLI 工具链

### 启动引擎
系统核心调度由 Python 实现的异步引擎驱动，通过挂载目标项目根目录作为工作区启动：

```bash
# 启动审计引擎，并指定待审计的项目根目录（如 dummy_project）
python -m src.main ./dummy_project
```

引擎启动后，会在目标目录下自动创建 `.a2a_bus/` 目录结构，并进入监听轮询模式。系统的运行日志将直接输出到控制台。

## 📚 详细设计文档

更详细的架构设计、调度逻辑和 A2A 通信协议请参考以下文档（位于 `doc/` 目录下）：

- [概要设计](doc/概要设计)
- [多智能体调度引擎与状态机设计](doc/多智能体调度引擎与状态机设计文档)
- [核心智能体提示词工程规范](doc/核心智能体提示词工程规范详细设计文档)
- [A2A 通信 JSON Schema 规范](doc/A2A%20通信%20JSON%20Schema%20详细设计)
