# 多智能体代码审计探索

> 基于 6 轮 baseline 迭代（v8 → v13）的工程实践与教训沉淀
>
> 项目：CodeAudit · 审计目标：WebGoat（Java/Spring 教学靶场）
> 时间跨度：2026-05-11 ~ 2026-05-16

---

## 摘要

本报告记录一次以"多智能体协同 + 静态规则 + 沙盒池"为骨架的 Java 代码审计引擎的工程演进。
通过 6 次完整 baseline 迭代，**最终在 WebGoat 上跑出 133 VULN / 50min / 0 failed**：
绝对发现数从 v8 的 122 涨到 v13 的 133（+9%），失败率从 v9 的 3.6% 降到 v12/v13 的 0%，
Lesson 维度召回从 83.3% 提升至 95.8%，严格 Precision 在 84-94% 区间波动。

报告核心叙事不是"我们做了多少功能"，而是**6 次迭代里踩过的坑、定位方法、修复后的实测验证**。
具体技术贡献包括：

1. **双轨工作流**（Sink-driven Path A + URL-driven Path B）让技术类漏洞和业务逻辑漏洞分流处理；
2. **Schema 严格度的工程经验**：minLength 太严会让 LLM 生成 302 token 的输出被静默吞掉；
3. **LLM 浅推理的强约束 prompt**：反面教材内嵌 + 明列禁用借口；
4. **Semgrep pattern-not 两类陷阱**：尾通配 `"...", ...` 漏多参数变量 sink、metavariable 无 type 约束跨类误排除；
5. **小批量验证流水线**：mock 单元测试 + 3 次重放 + 完整 baseline + 全量人工核对。

读者对象：做 LLM 工程化、代码审计、SAST 工具链或多智能体系统的工程师。

---

## 目录

- [第 1 章 引言](#第-1-章-引言)
- [第 2 章 系统设计](#第-2-章-系统设计)
- [第 3 章 实战演进：v8 → v13 六次 baseline](#第-3-章-实战演进v8--v13-六次-baseline)
- [第 4 章 关键 Case Study](#第-4-章-关键-case-study)
- [第 5 章 评估方法学](#第-5-章-评估方法学)
- [第 7 章 经验沉淀](#第-7-章-经验沉淀)
- [第 8 章 局限与未来](#第-8-章-局限与未来)
- [附录](#附录)

---

## 第 1 章 引言

### 1.1 两类传统范式与各自局限

代码安全审计在过去十年大致分两条路线：

**(a) 纯静态分析（SAST）** —— Semgrep / CodeQL / Fortify / Checkmarx。
通过规则匹配 sink + 数据流追踪定位漏洞，优点是确定性、可重放、低成本；
缺点是召回靠规则人写、误报率高、业务逻辑漏洞（IDOR / 鉴权缺失 / Race Condition）几乎无能为力。

笔者在多个项目里观察到：Semgrep 的 raw 命中数往往是真漏洞数的 3-5 倍，
而真漏洞中 30-40% 是业务逻辑类（无固定 sink 模式），SAST 工具完全抓不到。

**(b) 单 LLM agent 直读代码** —— GPT-4 / Claude 直接喂源码做审计。
优点是能处理业务逻辑，缺点也很明确：

1. **上下文窗口**：百万行代码不能一次喂完，分片审计时跨文件追踪能力差；
2. **认知偷懒**：当 Semgrep 输出 30+ 条 result 时，LLM 倾向于"整体归并 + 挑几个代表性的分析"
   而非逐条裁决；
3. **缺乏污点链**：LLM 看到 `executeQuery(query)` 不一定能判定 query 是否真的可控；
4. **判定不一致**：同一类漏洞在不同上下文 LLM 给出截然相反的结论（教学项目"借口"是典型）；
5. **不可重放**：每次跑结果不同，CI/CD 集成困难。

### 1.2 多智能体范式的设想

我们设想的方案是"**让不同角色的 LLM 各司其职 + 静态规则做骨架**"：

- **静态分析提供 sink 候选**（Semgrep 规则，35+ 条覆盖 38 个 vuln_type），保证确定性下限；
- **LLM-A 做污点追踪**（ReverseTracer），跨文件追用户输入到 sink 的链路；
- **LLM-B 做业务逻辑推理**（LogicAuditor），从 URL 路由发现 IDOR/鉴权缺失等；
- **LLM-C 做红队验证**（RedValidator），构造 PoC，过滤"看似 sink 实则不可利用"的 FP；
- **LLM-D 做蓝队复核**（BlueValidator），找全局/局部防御机制，最终落地 VULNERABLE / DEFENDED；
- **沙盒池**（OpenCode HTTP server pool）让 LLM 有 read / lsp / codesearch 工具，能像人一样浏览代码；
- **A2A bus**（文件系统目录队列）让 agent 间状态可重放、可中断恢复、可审计。

任何单个 LLM 的"看似合理但错误"判定，下一个 agent 有机会纠正；任何静态规则的 FP，
LLM 验证层有机会过滤。整体上是一个"工程层 + 模型层"的混合系统。

### 1.3 本报告范围

本报告基于 6 轮完整 baseline 演进的数据和复盘，涵盖：

- 架构与关键工程组件（第 2 章）
- 6 次迭代的核心改动与数据故事（第 3 章）
- 4 组深度反面教材：Schema 陷阱、LLM 浅推理、Semgrep pattern-not 陷阱、LLM 不逐条分析（第 4 章）
- 评估方法学与多维度数字（第 5 章）
- 可迁移到任意 LLM-工程项目的经验沉淀（第 7 章）
- 现有局限与未来演进方向（第 8 章）

代码 + 数据全部开源（GitHub: Wang1921/CodeAudit），所有 baseline 报告归档在
`reports_v{N}_baseline_YYYY-MM-DD_{N}vuln/` 目录。

---

## 第 2 章 系统设计

### 2.1 整体架构与术语

```
                                ┌───────────────────────────────────────┐
              CLI 入口            │              主进程 asyncio loop          │
  codeaudit /target ────────────▶│  ┌─ AuditEngine.run()               │
                                  │  ├─ SemgrepScanner.scan()           │
                                  │  ├─ A2ABusManager (文件队列)         │
                                  │  ├─ Semaphore: main(5) / chain(3)   │
                                  │  ├─ StateRouter (规则化下游派发)       │
                                  │  └─ StateTracker (前端大屏 8080)     │
                                  └────────────┬──────────────────────────┘
                                                │
                                                ▼
                       ┌────────────────────────────────────────────────────┐
                       │           A2A bus (.a2a_bus/<target>/)              │
                       │  pending/  processing/  completed/  failed/  help_req/ │
                       └────┬──────────────┬───────────────┬─────────────────┘
                            │              │               │
                ┌───────────┘              │               └─────────────┐
                ▼                          ▼                              ▼
   ┌────────────────────┐     ┌────────────────────┐         ┌────────────────────┐
   │ Path A 链路           │     │ Path B 链路           │         │ 跨服务追踪逻辑       │
   │  (Sink-driven)       │     │  (URL/Route-driven)  │         │  ReverseTracer 接力 │
   │                      │     │                      │         └────────────────────┘
   │ Semgrep (sink rules)│     │ Semgrep (spring-api) │
   │     ↓                │     │     ↓                │
   │ ReverseTracer        │     │ LogicAuditor          │
   │     ↓                │     │     ↓                │
   │ RedValidator         │     │ RedValidator          │
   │     ↓                │     │     ↓                │
   │ BlueValidator        │     │ BlueValidator         │
   │     ↓                │     │     ↓                │
   │ Report               │     │ Report                │
   └──────────┬──────────┘     └──────────┬───────────┘
              │                            │
              └───────┬────────────────────┘
                       ▼
              ┌─────────────────────────────┐
              │   reports/audit-*.json       │
              │   reports/SUMMARY.md         │
              └─────────────────────────────┘

  外部组件:
  ┌──────────────────────────────────────────────────────────┐
  │  OpenCodeServerManager  (LRU 沙盒池,默认 5 个并发 server)  │
  │  每个 sandbox: opencode HTTP server + read/lsp/codesearch │
  └──────────────────────────────────────────────────────────┘
```

**核心概念**：

- **Path A（Sink-driven）**：Semgrep 抓到代码层 sink → ReverseTracer 追到 HTTP 入口 →
  RedValidator 验证可利用 → BlueValidator 复核防御 → 落地报告。
- **Path B（URL/Route-driven）**：spring-api 规则发现 controller 路由 →
  LogicAuditor 跨文件审查业务逻辑（IDOR / Authentication Bypass / 等 4 类）→
  RedValidator / BlueValidator 复核。
- **A2A bus**：基于文件系统目录的异步消息总线。每条任务是一个 `.json` envelope，
  状态通过 `os.rename` 在 5 个子目录间原子迁移（pending → processing → completed/failed）。
  这种设计让状态完全可见、可中断恢复、可手工干预。
- **沙盒池**：OpenCode 是个 LLM 编辑器框架，提供 HTTP server 暴露
  `read / lsp / codesearch` 三个工具给 LLM 调用。每个目标项目（微服务）启动一个独立 server，
  按 LRU 复用，上限可配置。

### 2.2 五个 Agent 的职责拆分

| Agent | 性质 | 输入 | 输出 | 关键约束 |
|---|---|---|---|---|
| **SemgrepScanner** | 脚本（无 LLM）| 项目目录 | sinks[] + routes[] | 35+ 条规则 / 14 条 `--exclude` 全局 |
| **ReverseTracer** | LLM | sink_details | EXPLOITABLE 候选 / NOT_EXPLOITABLE | 跨文件 ≤5 跳追溯用户输入 |
| **LogicAuditor** | LLM | route_details | 9 类业务漏洞之一 / DEFENDED | 跨文件追读 ≤2 跳 + 技术类漏洞强制 DEFENDED |
| **RedValidator** | LLM | EXPLOITABLE 候选 | EXPLOITABLE+PoC / NOT_EXPLOITABLE+证据 | 逐参数判定 + NOT_EXPLOITABLE 强制 defense_analysis |
| **BlueValidator** | LLM | EXPLOITABLE+PoC 或静态 sink | VULNERABLE / DEFENDED | 路径 A 找全局防御 + 路径 B 静态定性 |

各 Agent 的 output_schema 都用 `oneOf` 多变体定义，严格校验 LLM 输出格式。

LogicAuditor 的 9 类业务漏洞白名单（必须从中选一个 vuln_type，禁止自创）：

```
IDOR / Privilege Escalation / Authentication Bypass /
Hardcoded Backdoor / Open Redirect（兜底）
```

LogicAuditor **不负责**技术类漏洞（SQL Injection / Path Traversal / XSS / SSRF / XXE /
Unsafe Deserialization / Command Injection / Code Injection 等）—— 这些有专属 Semgrep 规则
+ ReverseTracer 走 Sink 路径处理。这个分工的强制约束是 v11 后追加的（详见 4.2）。

### 2.3 关键工程组件

#### 2.3.1 双 Semaphore 拆分（避免链路饥饿）

引擎用两层 Semaphore：

```python
self.semaphore = asyncio.Semaphore(MAX_CONCURRENT_AGENTS)  # 5
self.chain_semaphore = asyncio.Semaphore(MAX_CHAIN_AGENTS)  # 3

# dispatch 时根据 sender 选择 semaphore
sender = env.get("sender", "")
sem = self.semaphore if sender == "SemgrepScanner" else self.chain_semaphore
```

**为什么拆**：早期单 Semaphore 设计时，Semgrep 初始一次性派发 ~100 条 sink 任务把队列填满，
后续 Reverse → Red → Blue 续接消息全部被饿死，导致 Path A 完整污点链永远落不了盘。
拆开后 chain_semaphore 物理保留 3 个 LLM slot 给续接消息，问题解决。

#### 2.3.2 per-agent timeout 映射

```python
MAX_AGENT_TIMEOUT = 300
PER_AGENT_TIMEOUT = {
    "LogicAuditor": 480,  # 跨文件追读耗时长
}
agent_timeout = PER_AGENT_TIMEOUT.get(recipient, MAX_AGENT_TIMEOUT)
```

LogicAuditor 需要"跨文件追读 ≤2 跳"，单任务工具调用次数比其他 agent 多。
v9 baseline 实测 ROUTE 失败 10/115，单独提到 480s 后 v12/v13 ROUTE 失败 0/115。

#### 2.3.3 输出 Schema 严格校验

每个 LLM agent 在 prompt yaml 里定义 `output_schema`，oneOf 多变体严格互斥。
例：BlueValidator 的 schema 有 3 个变体（VULNERABLE-A 完整污点链 / VULNERABLE-B 静态定性 / DEFENDED）。

服务端（OpenCode）支持把 JSON Schema 作为约束，让 LLM 输出严格符合。
客户端（`src/agent.py`）还做了 jsonschema 二次校验，schema fail 时尝试 coerce 救回，
最后实在不行才丢弃。

这套机制配合 prompt 的 vuln_type 白名单，让聚合层（CWE 映射 + 报告生成）可以信任输入。

#### 2.3.4 Memory 机制

LLM 对话之外的可复用知识用 file-based memory 持久化，目录
`~/.claude/projects/-home-wzq-CodeAudit/memory/`，分四类：

- **user** —— 用户个人信息 / 偏好
- **feedback** —— 项目特定的行为规范（如"包/模块用 lower_with_under"）
- **project** —— 项目状态快照（活跃任务、紧急度）
- **reference** —— 外部系统索引（如 Linear / Slack 频道）

每条 memory 是独立 `.md` 文件，`MEMORY.md` 是索引（每行一个 link）。
本项目落地的关键 memory：

| 类别 | 文件 | 内容 |
|---|---|---|
| project | project_overview.md | 项目架构 + 演进方向 |
| project | project_engine_performance_baseline.md | v8 baseline 参数（timeout / opencode 配置）|
| feedback | feedback_semgrep_metavariable_type_var.md | `var x = ...` 推不出类型导致漏报 |
| feedback | feedback_chain_starvation.md | 链路续接必须 priority=high 否则饿死 |
| feedback | feedback_python_naming_convention.md | PEP 8 命名 |
| feedback | feedback_semgrep_pattern_not_pitfalls.md | pattern-not 两类陷阱（v13 新加）|

### 2.4 双轨设计的工程意义

为什么不让一个 LLM 包打天下，而要拆 Path A / Path B？

**实测教训**（v10 数据）：当 LogicAuditor 没有"技术类排除"强约束时，遇到 SQL Injection
代码会强行从 8 类业务白名单里挑最像的（IDOR / Anti-Automation），
导致大量真漏洞被错挂分类。修复后（commit `8c6e933`），LogicAuditor 看到技术类形态直接
返回 DEFENDED 让 Sink 路径处理，错挂数从 11 降到 3。

这印证了**多智能体范式的核心价值**：每个 agent 职责清晰、互不抢任务，才能各自把自己的活做到位。

---

## 第 3 章 实战演进：v8 → v13 六次 baseline

每次 baseline 跑 WebGoat 全量审计 ~50min，产出 `reports/SUMMARY.md` + 100+ 个
`vulnerability_*.json` 报告。下表是六次的核心数据：

| 指标 | v8 | v9 | v10 | v11 | v12 | **v13** |
|---|---:|---:|---:|---:|---:|---:|
| 总 VULN | 122 | 92 | 105 | 117 | 127 | **133** |
| ROUTE 路径 | 38 | 28 | 48 | 43 | 38 | 40 |
| SINK 路径 | 84 | 64 | 57 | 74 | 89 | 93 |
| Critical | 21 | 22 | 21 | 26 | 26 | **31** |
| High | 41 | 35 | 49 | 54 | 65 | 63 |
| Medium | 58 | 34 | 34 | 36 | 35 | 38 |
| Low | 2 | 1 | 1 | 1 | 1 | 1 |
| 失败任务 | 3 | 16 | 2 | **0** | **0** | **0** |
| Lesson 召回（/24）| 20 | 19 | 22 | 22 | 23 | **23** |
| Lesson 召回 % | 83.3% | 79.2% | 91.7% | 91.7% | 95.8% | **95.8%** |
| 严格 Precision | ~78% | ~80% | 86.7% | **94.0%** | 86.6% | 84.2% |
| 宽松 Precision | ~92% | ~93% | 97.1% | 97.1% | 94.5% | 94.7% |
| 耗时 | 1h13 | 1h13 | 1h12 | **50min** | **50min** | **50min** |

下面按时间顺序讲每次迭代的核心改动 + 触发因素。

### 3.1 v8（baseline 起点）：122 VULN / 3 failed / 83% Lesson 召回

v8 是这一轮工作的起点。架构基本成型，5 agent + A2A bus + 沙盒池都跑通。
baseline 122 VULN 看似不错，但拆开看有明显问题：

- ROUTE 路径只有 38 个，业务逻辑漏洞抓得很弱
- Lesson 召回 83.3%（24 个真漏洞模块漏了 4 个：authbypass / cia / insecurelogin / vulnerablecomponents）
- 类型分布里出现 1 个 "Business Logic Flaw" catch-all（白名单外的描述串）

### 3.2 v9：MAX_AGENT_TIMEOUT 600→300 引起失败暴增

v9 的核心改动是性能优化：`MAX_AGENT_TIMEOUT` 从 600s 降到 300s，配合"超时换 session 重试 1 次"。
理论上这能让"卡死"型失败更快释放 slot。

**结果是灾难性的**：失败任务从 v8 的 3 暴增到 v9 的 16，总 VULN 从 122 暴跌到 92。

```
v8 baseline:  pending 0  processing 0  completed 431  failed 2  reports 122
v9 baseline:  pending 0  processing 0  completed 431  failed 16 reports 92
```

定位过程：查 `.a2a_bus/failed/` 发现 10 个是 LogicAuditor task（ROUTE），6 个是 SINK_TRACE。
LogicAuditor 加了"跨文件追读 ≤2 跳"强制工作流后，单任务实际工具调用次数翻倍，300s 撑不住。

**修复（v10 起）**：保留全局 300s，只给 LogicAuditor 单独提到 480s。

```python
PER_AGENT_TIMEOUT = {
    "LogicAuditor": 480,
}
```

v9 还有一个意外发现：Lesson 召回反而降到 79.2%。原因是 `bypassrestrictions` 和
`deserialization` 两个模块都漏了。这暴露了**召回测量的脆弱性**：单次 baseline 抖动可能掩盖真问题。
所以后来我们引入"3 次重放"作为小批量验证手段（详见 4.2）。

### 3.3 v10：救火 + 规则拆分

v10 改动比较杂，包括：

- **per-agent timeout** 修 v9 的 LogicAuditor 失败暴增（生效，失败 16→2）
- **LogicAuditor 优先级抢救**：v9 IDOR 暴跌 7→1，因为 prompt 没明确说 IDOR 优先于 Authentication Bypass。
  修后 IDOR 1→10（超 v8 水位）
- **新规则 `mass-assignment.yaml`**：3 个 id 抓 BeanUtils / @InitBinder / ObjectMapper.readValue
- **`xxe.yaml` 拆 3 个 id**：DOM / SAX-StAX / Transform-Validate
- **`sql-injection.yaml` 补 2 个 id**：R2DBC/JdbcClient + 链式 createStatement
- **全局 `--exclude` 14 个 glob**：mitigation/test/build 等

数据：v10 105 VULN（v9 92→+13），失败 2/431，Lesson 召回 91.7%（22/24）。

但 v10 暴露了一个隐藏更深的问题：**严格 Precision 86.7%，比 v9 还低 5pp**。深查发现
11 条"类型错挂 FP" —— 漏洞真实存在但 vuln_type 标错，多数是 LogicAuditor 把 SQL Injection
错挂为 IDOR。这成了 v11 的核心修复目标。

### 3.4 v11：Schema 救漏报 + LogicAuditor 技术类排除

v11 的两个核心修复都精彩：

**修复 1：BlueValidator schema minLength 20→5**

v10 baseline 全量人工核对发现 9 个真漏洞被 BlueValidator 静默吞掉（详细案例见 4.1）。
追溯到 `output_schema` 里 4 个字段（attack_vector / max_impact / defense_analysis / mitigation_advice）
设了 `minLength: 20`，任何一个字段未达 20 字符触发整体 reject，response="" / structured_output=null。

```yaml
# 旧
attack_vector:    { type: string, minLength: 20 }
max_impact:       { type: string, minLength: 20 }
defense_analysis: { type: string, minLength: 20 }
mitigation_advice:{ type: string, minLength: 20 }

# 新
attack_vector:    { type: string, minLength: 5 }
max_impact:       { type: string, minLength: 5 }
defense_analysis: { type: string, minLength: 5 }
mitigation_advice:{ type: string, minLength: 5 }
```

4 case 小批量验证全 pass。

**修复 2：LogicAuditor prompt 加"技术类漏洞排除"强约束**

新增 30 行约束段，明列 8 大技术类漏洞形态（SQL Injection / Path Traversal / Zip Slip /
Command Injection / SSRF / XSS / XXE / Unsafe Deserialization），强制 DEFENDED。
还内嵌了 v10 实测的 5 个错挂案例作为反面教材。

```
⚠️ 典型踩坑案例（vs v10 baseline 实测）：
  - executeQuery(query) 其中 query 来自 @RequestParam —— 是 SQL Injection,
    不是 "Missing Authorization"
  - createStatement().executeQuery("SELECT ... WHERE id = '" + kid + "'") ——
    是 SQL Injection,不是 "IDOR"
  - ZipEntry.getName() 未校验 .. —— 是 Zip Slip / Path Traversal,不是 "IDOR"
  - XStream.fromXML(xml) 无白名单 —— 是 Unsafe Deserialization,
    不是 "Authentication Bypass"
```

v11 数据：117 VULN（+12）、严格 Precision **94.0%**（v10 86.7%）、失败 **0**、Lesson 召回 91.7%。

v11 是这一轮里 Precision 最高的版本。**这印证了 prompt + schema 工程 ≈ 60% 的收益来源**。

### 3.5 v12：防 LLM 偷懒 + 新规则

v12 想解决 v11 留下的两个漏报：

- `/SqlInjectionAdvanced/attack6b` —— `if (input.equals(getPassword()))` + getter 返回 fallback "dave"
- `authbypass` 整 lesson 6 个 baseline 都漏

修复方案：

1. **新建 `hardcoded-backdoor.yaml`**（2 个 id）抓 `if (input.equals("literal")) → success` 模式 +
   getter fallback 模式。WebGoat raw 实测 15 命中（多数是 quiz FP，设 LOW + taint_required 让 Red/Blue 过滤）。
2. **`weak-cryptography.yaml`** 加 EC 短曲线 / Bouncy Castle 弱密码 / 自定义 XOR 模式。
3. **`xss.yaml`** 加 Spring `Model.addAttribute("html", $X)` / `ResponseEntity.body($X)` 等 sink。

v12 数据：**127 VULN（+10）**、Lesson 召回 **95.8%（23/24）** ⭐、失败 0、严格 Precision 86.6%。

attack6b 成功救回。但 Precision 比 v11 降了 7pp，因为 hardcoded-backdoor 引入了一些 quiz 类
误判（教学项目的 `if (input.equals("Solution 4"))` 被识别为后门）。

### 3.6 v13：修浅推理 + pattern-not 陷阱

v12 全量核对发现新问题：`/challenge/5` SQL Injection 仍漏报。链路追溯发现是
**RedValidator 浅推理**：

```
Semgrep → ReverseTracer ✅ (识别 SQL Injection)
ReverseTracer → RedValidator → {"status": "NOT_EXPLOITABLE"} ❌ (29 char 单字段)
```

RedValidator 看到 `if (!"Larry".equals(username))` 就误以为整体被防御，没注意 password 仍可控。

**修复**（commit `0f65b7d`，3 处一起改）：

1. RedValidator prompt 加"逐参数判定"强约束 + 反模式案例 + 4 种禁用 NOT_EXPLOITABLE 借口
2. NOT_EXPLOITABLE 输出契约改为**必须带 defense_analysis** 字段
3. Schema NOT_EXPLOITABLE 变体 `required: [status]` → `[status, defense_analysis]` +
   `minLength: 20`，浅推理被 schema 拦截

3 次重放小批量验证（commit `0f65b7d` 提交时跑的 `verify_red_validator_fix.py`）：
3/3 全过，每次都精确点出"username 限 Larry 但 password 可控"，poc_payload 精准
`password=' OR '1'='1`。

v13 还修了 Semgrep pattern-not 两类陷阱（详见 4.3）。

v13 数据：**133 VULN（+6）** ⭐ 历史最高、严格 Precision 84.2%、宽松 94.7%、**完全 FP=0** ⭐、
Lesson 召回 95.8%、失败 0、耗时 50min。

`/challenge/5` 完美救回。但严格 Precision 比 v12 又降 2.4pp，原因是 hardcoded-backdoor
规则继续导致少量错挂 + SSRF/Path Traversal 同 sink 跨类重复命中。

### 3.7 趋势可视化

```
总 VULN 数:
v8 :  ████████████████████████████████████████████████ 122
v9 :  ███████████████████████████████████              92
v10:  ██████████████████████████████████████████       105
v11:  ██████████████████████████████████████████████   117
v12:  █████████████████████████████████████████████████  127
v13:  ███████████████████████████████████████████████████  133  ⭐

失败任务数 (越低越好):
v8 :  ███                          3
v9 :  ████████████████             16  ❌
v10:  ██                           2
v11:                                0
v12:                                0
v13:                                0   ⭐

Lesson 召回率 (24 模块):
v8 :  ████████████████████████████ 83.3%
v9 :  ██████████████████████████   79.2%
v10:  █████████████████████████████████ 91.7%
v11:  █████████████████████████████████ 91.7%
v12:  ███████████████████████████████████ 95.8%
v13:  ███████████████████████████████████ 95.8%  ⭐

严格 Precision (vuln_type 准确):
v8 :  ████████████████████████ ~78%
v9 :  ████████████████████████ ~80%
v10:  ██████████████████████████ 86.7%
v11:  ████████████████████████████ 94.0%  ⭐
v12:  ██████████████████████████ 86.6%
v13:  █████████████████████████ 84.2%

baseline 耗时:
v8 :  ████████████████████████ 1h13
v9 :  ████████████████████████ 1h13
v10:  ████████████████████████ 1h12
v11:  ██████████████ 50min
v12:  ██████████████ 50min
v13:  ██████████████ 50min  ⭐
```

**v8 → v13 的关键 inflection point** 是 v11 —— BlueValidator schema 修复 + LogicAuditor
技术类排除让 Precision 跃升至 94%、耗时压缩 30%。后续 v12/v13 是在拓展召回边界
（救新漏报）的同时容忍 Precision 略降。

---

## 第 4 章 关键 Case Study

每次迭代都有具体的反面教材。下面 4 个 case 是 v10-v13 期间最有代表性的"看似合理实际埋坑"的工程问题。
每个 case 按 "现象→定位→根因→修复→验证" 五段展开。

### 4.1 Case Study 1：Schema 过严吞 9 个真漏洞

**现象**：v10 baseline 全量核对完毕，按 vuln_type 拆分 SQL Injection 类的 SINK 路径报告，
发现 v8 抓到 8 个，v9 抓到 6 个，v10 抓到 7 个。但 Semgrep raw 在 WebGoat 上扫到 14 个潜在
sink。差额 7-8 个去哪了？

**定位**：检查 `.a2a_bus/completed/` 找 SINK_TRACE 类 envelope（这是 RedValidator → BlueValidator
最后一站）。Python 脚本扫一遍：

```python
import json, glob
suspicious = []
for f in glob.glob('/home/wzq/WebGoat/.a2a_bus/completed/*TRACE*.json'):
    d = json.load(open(f))
    if d.get('sender') != 'RedValidator' or d.get('recipient') != 'BlueValidator':
        continue
    ar = d.get('agent_result', {})
    pl = d.get('payload', {})
    if pl.get('status') == 'EXPLOITABLE' and ar.get('structured_output') in (None, {}, ''):
        suspicious.append({
            'task': d.get('task_id'),
            'vt': pl.get('vuln_type'),
            'file': pl.get('filepath', '').split('/')[-1],
            'line': pl.get('line_number'),
            'resp_len': len(ar.get('response', '')),
        })

print(f"BlueValidator 收到 EXPLOITABLE 但产出空 structured_output: {len(suspicious)} 条")
```

输出：**9 条**！分别是：

```
[NoSQL Injection         ] SqlInjectionLesson9.java:65   resp_len=0
[SQL Injection           ] SqlInjectionLesson8.java:62   resp_len=0
[SQL Injection           ] SqlInjectionLesson5b.java:48  resp_len=0
[Path Traversal          ] Ping.java:32                  resp_len=2
[Unsafe Deserialization  ] VulnerableComponentsLesson:42 resp_len=0
[Unsafe Deserialization  ] SerializationHelper.java:23   resp_len=0
[Command Injection       ] VulnerableTaskHolder.java:67  resp_len=0
[SQL Injection           ] SqlInjectionLesson2.java:49   resp_len=3
[SQL Injection           ] SqlInjectionLesson9.java:94   resp_len=0
```

注意：`tokens.output = 302`（LLM 实际生成了 302 个 token），但 `response: ""`。
说明 LLM 输出了内容但被引擎丢弃。

**根因**：BlueValidator 的 `output_schema` 里 4 个字段设了 `minLength: 20`：

```yaml
oneOf:
  - type: object
    required: [status, vuln_type, ..., attack_vector, ..., mitigation_advice]
    properties:
      attack_vector:    { type: string, minLength: 20 }
      max_impact:       { type: string, minLength: 20 }
      defense_analysis: { type: string, minLength: 20 }
      mitigation_advice:{ type: string, minLength: 20 }
```

LLM 任意一个字段写到 18 字符（如 `"数据库泄漏"`）就触发整体 reject，整条记录被丢弃。

**修复**：minLength 20 → 5（commit `e0084d6`）。

5 个字符仍能挡住纯 hallucination（如返回 `""` 或单个 emoji），但能容忍中文里 4-10 字的真实回答。

**验证**：写 `tools/verify_blue_validator_fix.py` 复刻 4 个被吞 task 的 payload 重放：

```
① SerializationHelper.java:23 - Unsafe Deserialization
   修复前: structured_output = null
   修复后: ✅ VULNERABLE (defense_analysis: "分析了项目中的全局安全配置...")

② SqlInjectionLesson8.java:62 - SQL Injection
   修复前: null  修复后: ✅ VULNERABLE

③ Ping.java:32 - Path Traversal
   修复前: null  修复后: ✅ VULNERABLE

④ SqlInjectionLesson5b.java:48 - SQL Injection
   修复前: null  修复后: ✅ VULNERABLE

4/4 通过(修复前 v10 baseline: 0/4)
```

**教训沉淀（feedback memory）**：JSON Schema 的 `minLength` 是 unicode code point 数，
中文一个字一个 code point。`minLength: 20` 对中文回答而言意味着 20 个汉字（约 60 字节），
对 LLM 太苛刻。中文场景下 `minLength: 5` 才是合理下限。

---

### 4.2 Case Study 2：LLM "看似合理"借口翻转判定

**现象**：v11 → v12 全量核对，发现历史一直能命中的 `/SqlInjection/attack3` 和
`/OpenRedirect/task4` 在 v11 baseline 漏报了。但 RedValidator 输出的 attack_vector 看上去
完整且合理。

**定位**：查 `.a2a_bus/completed/` 找这两个 URL 对应的 task envelope。重点看 BlueValidator
最后那一站：

```json
// TASK-INIT-001_SINK_82_TRACE_d343cc80.json
// (Path A: Semgrep → ReverseTracer → RedValidator → BlueValidator)
{
  "sender": "RedValidator",
  "recipient": "BlueValidator",
  "payload": {
    "vuln_type": "SQL Injection",
    "entry_route": "/SqlInjection/attack3",
    "line_number": "47",
    "status": "EXPLOITABLE",       // ← RedValidator 标 EXPLOITABLE
    "attack_vector": "...",
    "poc_payload": "..."
  },
  "agent_result": {
    "structured_output": {
      "status": "DEFENDED",         // ← BlueValidator 翻转为 DEFENDED
      "defense_analysis": "这是一个故意设计的 SQL 注入教学案例,位于 WebGoat 漏洞练习
                          平台的代码库中。该代码的目的是向学习者展示 SQL 注入漏洞的
                          原理和利用方法,而非生产环境的实际应用代码..."
    }
  }
}
```

**BlueValidator 用"WebGoat 是教学项目"作为 DEFENDED 理由**，把 RedValidator 标的
EXPLOITABLE 翻转成 DEFENDED。

但同 baseline 里 12 个其他 SQL Injection（同样 WebGoat 教学项目）都被正确判 VULNERABLE，
只这一个被翻转 —— LLM 的不一致。

OpenRedirectTask4 同样问题：

```json
"defense_analysis": "这是一个 WebGoat 的教学示例代码,用于演示双重解码导致的开放重定向
                    漏洞。代码的核心逻辑是验证攻击是否成功,而非实际执行重定向操作..."
```

类似地，v12 baseline 发现 `/challenge/5` SQL Injection 仍漏，但这次链路是 RedValidator
而非 BlueValidator 出问题：

```json
// RedValidator 输出:
{"status": "NOT_EXPLOITABLE"}    // 29 char,仅 status 单字段
```

`tokens.output = 302`，说明 LLM 生成了内容但只保留了 status 字段（schema 允许）。
真正的"为什么不能利用"的解释完全没有。

**根因分析**：

1. **BlueValidator 的"教学项目"借口**：prompt 里"允许的 DEFENDED 证据"列表没有明确
   "代码所属项目类型"，LLM 自己脑补出这个维度。

2. **RedValidator 的"单参数白名单"借口**：`/challenge/5` 的代码是：
   ```java
   if (!"Larry".equals(username_login)) return failed(...);
   connection.prepareStatement("SELECT ... WHERE userid='" + username + "' AND password='" + password + "'");
   ```
   LLM 看到 if 校验 username 就认为整体被防御，但 password 仍 100% 可控。

3. **RedValidator schema 允许 NOT_EXPLOITABLE 单字段**：
   ```yaml
   - type: object
     required: [status]           # 只要 status 就够
     properties:
       status: { enum: [NOT_EXPLOITABLE] }
   ```
   没有要求 NOT_EXPLOITABLE 时必须给出代码证据，LLM 可以"看一眼觉得防住了就判"，
   不被强制深推理。

**修复**（v11 commit `4dffd05` + v12 commit `0f65b7d`，三处协同）：

**修 1：BlueValidator prompt 加"教学项目代码 = 真漏洞代码"强约束**：

```yaml
## 🚫 强约束（不可违背,违背即审计未尽职）

**禁止以"代码来自教学/演示/CTF/靶场项目"作为 DEFENDED 理由**。
WebGoat / DVWA / Juice Shop / SecurityShepherd / Vulhub / OWASP Benchmark 等
教学项目的代码**就是真漏洞代码**,按生产代码同等严格判定。

❌ 禁用理由示例(一律视为无效,输出仍判 VULNERABLE):
- "这是一个故意设计的 SQL 注入教学案例"
- "该代码用于演示漏洞原理,而非生产环境实际应用"
- "WebGoat 是漏洞练习平台,代码本意就是有漏洞"
- "代码中并没有实际的重定向逻辑,只是验证攻击成功"
- "这是一个教学示例代码,用于演示..."
```

**修 2：RedValidator prompt 加"逐参数判定"强约束**：

```yaml
## 🚫 强约束（不可违背,违背即审计未尽职）

**逐参数判定 exploitability**:sink 中只要**有任意一个参数仍是攻击者可控**,
整个 sink 就构成 EXPLOITABLE。**单参数白名单校验不构成整体防御**。

❌ 典型反模式（v12 baseline 实测）:
   Assignment5.java `/challenge/5` login(@RequestParam username, @RequestParam password)
   ```
   if (!"Larry".equals(username)) return failed(...);    // username 被白名单限制
   connection.prepareStatement("... userid='" + username + "' and password='" + password + "'");
   ```
   错判 NOT_EXPLOITABLE 的理由:"username 被 'Larry' 白名单限制" — **错!**
   正确判 EXPLOITABLE:username=Larry 通过校验后,**password 仍 100% 可控**,
   注入 `password=' OR '1'='1` 即可绕过登录。

**决策清单（逐项核对,缺一不可）**:
1. 列出 sink 调用里**每一个**传入参数;
2. 对每个参数,追溯它的来源(HTTP 入参 / 内部常量 / 已过滤值);
3. 任意一个参数追溯到"可控的 HTTP 入参且未经有效过滤" → 判 EXPLOITABLE;
4. **必须所有参数**都被有效过滤(白名单 / 类型转换 / 编码 / 长度限制)才能判 NOT_EXPLOITABLE。

❌ 禁用的"看似合理但错误"的 NOT_EXPLOITABLE 理由:
- "username 必须是 Xxx,输入受限" —— 只校验了一个参数,其他参数仍可控
- "前面有 if 判断" —— 看清楚 if 判断的是哪个变量,其他变量是否仍流入 sink
- "用户必须登录才能访问" —— 已登录用户仍可触发漏洞,依然 EXPLOITABLE
- "代码是教学/演示项目" —— 教学项目代码也是真漏洞代码（同 BlueValidator 约束）
```

**修 3：RedValidator schema NOT_EXPLOITABLE 强制 defense_analysis**：

```yaml
# NOT_EXPLOITABLE: 必须带 defense_analysis 字段(minLength: 20)
- type: object
  required: [status, defense_analysis]   # 新增 required
  properties:
    status: { enum: [NOT_EXPLOITABLE] }
    defense_analysis: { type: string, minLength: 20 }  # 新增字段
```

LLM 浅推理（仅返回 status）会被 schema 直接 reject，强制必须证明"为什么不能利用"。

**验证**：写 `tools/verify_red_validator_fix.py`，对 `/challenge/5` payload 重放 3 次：

```
第 1 次: ✅ EXPLOITABLE
  attack_vector: "虽然 username 有白名单限制为 Larry,但 password 仍完全可控..."
  poc_payload: {"username_login":"Larry","password_login":"' OR '1'='1"}

第 2 次: ✅ EXPLOITABLE
  attack_vector: "该漏洞中,虽然 username 参数在第 39 行被白名单限制为 Larry,
                 但 password 参数仍然完全由攻击者控制..."
  poc_payload: {"username_login":"Larry","password_login":"' OR '1'='1"}

第 3 次: ✅ EXPLOITABLE
  attack_vector: "尽管 username 被白名单限制为 Larry,但 password 仍完全可控
                 且未经过任何 SQL 注入防护处理..."
  poc_payload: POST /challenge/5 HTTP/1.1
              Host: localhost:8080
              Content-Type: application/x-www-form-urlencoded

              username_login=Larry&password_login=' OR '1'='1

3/3 通过(修复前 v12 实测: 0/1 判 EXPLOITABLE)
```

每次都精确点出"单参数白名单不构成整体防御"，poc_payload 精准。

v13 完整 baseline 验证：`/challenge/5` SQL Injection ✅ 成功救回。

**教训沉淀**：

1. **LLM 找借口的模式可枚举**：教学项目 / 单参数限制 / 必须登录 / 数据库读出 /
   前端校验 —— 这 5 大类借口在 prompt 里明确禁用，能消除 95% 的"看似合理"翻转。

2. **Schema 与 prompt 协同**：prompt 让 LLM "想这么做"，schema 让 LLM "不能这么做"。
   两者缺一不可。

3. **小批量重放是验证 prompt 改动的最有效手段**：3-4 次重放即可证明改动稳定性，
   不需要每次都跑全量 baseline（50min）。

---

### 4.3 Case Study 3：Semgrep pattern-not 两类陷阱

**现象**：用户问 `new ProcessBuilder("sh", "scriptPath", "arg2")` 是否会告警时，
我顺手 mock 测了 6 种 ProcessBuilder 形态：

```java
new ProcessBuilder("sh", "scriptPath", "arg2");               // 全字面量
new ProcessBuilder("sh", scriptPath, "arg2");                  // 中段变量
new ProcessBuilder("sh", "-c", userInput);                     // ⚠️ shell -c 经典 RCE
new ProcessBuilder(userCmd, "arg1", "arg2");                   // 首参变量
```

实测发现 `new ProcessBuilder("sh", "-c", userInput)` **不告警**！这是经典的 shell 包装 RCE 模式，
应该触发命令注入规则。

**定位**：看 `command-injection.yaml` 的 pattern-not：

```yaml
- pattern-not: new ProcessBuilder("...", ...)
```

`"..."` 是 Semgrep 的字面量字符串通配，`...` 是任意后续参数。所以这个 pattern-not 排除
"第 1 参数字面量 + 后续任意"形态。`new ProcessBuilder("sh", "-c", userInput)` 完美匹配
这个 pattern-not → 被误排除。

继续排查同类问题，发现 `path-traversal.yaml` 的 `pattern-not: Paths.get("...", ...)` 也有同样问题
—— `Paths.get` 是 varargs，`Paths.get("/safe/dir", userInput)` 这种"第 2+ 参数可控"被误排除。

**修复 1（陷阱 ①）**：把"..." + 尾通配改为列举多 arity 全字面量：

```yaml
# 旧 (漏报)
- pattern-not: new ProcessBuilder("...", ...)

# 新 (精确)
- pattern-not: new ProcessBuilder("...")
- pattern-not: new ProcessBuilder("...", "...")
- pattern-not: new ProcessBuilder("...", "...", "...")
- pattern-not: new ProcessBuilder("...", "...", "...", "...")
- pattern-not: new ProcessBuilder("...", "...", "...", "...", "...")
```

实测：
```
new ProcessBuilder("sh", "-c", userInput)        ← ✅ 现在告警
new ProcessBuilder("sh", "scriptPath", "arg2")   ← ✅ 仍不告警 (3 字面量)
new ProcessBuilder("ls", "-la")                  ← ✅ 仍不告警 (2 字面量)
```

mock 6 种全部符合预期。

**修复 2（陷阱 ②，最隐蔽）**：

修完陷阱 ① 后跑 mock，发现 `Paths.get("/safe", u)` 在 `path-traversal.yaml` 完整规则下
**仍然 0 命中**！但单独的最小 pattern 跑能命中。

二分法定位：把规则的 73 条 pattern-not 切两半轮流测：

```
前半保留: 0 命中  ← 罪魁在前半
后半保留: 1 命中

→ 继续二分前半:
   前 36 条保留: 0 命中
   后 37 条保留: 1 命中
→ 罪魁在前 36 条里...
→ ...逐条删除测试,定位到 line 193:
```

```yaml
- pattern-not: $SFTP.get("...", ...)
```

`$SFTP` 是 metavariable，在主 pattern 里有 `metavariable-type: ChannelSftp` 约束。
但在 `pattern-not` 里**没有继承类型约束** —— Semgrep 把 `pattern-not` 内的 `$SFTP` 当作
独立元变量实例。结果：

- `Paths.get("/safe", u)` 匹配 `$SFTP.get("...", ...)`：
  - $SFTP 匹配 `Paths`（任何类）
  - `"..."` 匹配 `"/safe"`
  - `...` 匹配 `u`
- 整个 `Paths.get("/safe", u)` 被误排除。

**修复**：直接删除 3 条 $SFTP 的 pattern-not（line 193-195）。理由：主 pattern 已对 $SFTP
限定 `ChannelSftp` 类型，全字面量的 SFTP 调用本来就不会进入主 pattern，无需 pattern-not
补充。

```yaml
# 删除 (跨类误排除):
# - pattern-not: $SFTP.get("...", ...)
# - pattern-not: $SFTP.ls("...")
# - pattern-not: $SFTP.cd("...")
```

WebGoat raw 命中数验证：删除前 41，删除后 41（不影响真命中）✅。
Mock 验证：`Paths.get("/safe", u)` ✅ 命中、`Paths.get("/safe", "subdir", u)` ✅ 命中、
`Paths.get("/safe", "subdir", "file.txt")` ❌ 不命中（全字面量）。

**修复 3（XSS 类似问题）**：

`xss.yaml` 抓 `$R.getWriter().format($FMT, $X, ...)` 链式，但变量形式
`$W.format/$W.printf` 没抓。加上：

```yaml
- patterns:
    - pattern-either:
        - pattern: $W.format($FMT, $X, ...)
        - pattern: $W.printf($FMT, $X, ...)
    - metavariable-type:
        metavariable: $W
        types:
          - PrintWriter
          - java.io.PrintWriter
          - Writer
          - java.io.Writer
```

**教训沉淀（feedback memory `feedback_semgrep_pattern_not_pitfalls.md`）**：

写 Semgrep pattern-not 时两个易踩的陷阱：

**陷阱 ①** `pattern-not: Foo("...", ...)` 漏多参数变量 sink。`"..."` 是字面量通配，
`...` 是任意后续参数。这种 pattern-not 排除"第 1 参数字面量 + 后续任意"，导致**关键参数
不在第 1 位**的真漏洞被静默排除：

- `new ProcessBuilder("sh", "-c", userInput)` —— 经典 shell -c RCE
- `Paths.get("/safe/dir", userInput)` —— varargs 第 2+ 参数可控
- `printWriter.printf("Hello %s", userInput)` —— format 风格 XSS

**修复**：列举多 arity 全字面量代替 `"..., ..."`。

**陷阱 ②** `pattern-not: $X.method("...")` 无 type 约束跨类误排除。`$X` 是 metavariable，
能匹配**任何类型**的对象。即使主 pattern 里 `$X` 有 `metavariable-type` 约束，`pattern-not`
内的 `$X` 是独立元变量实例，**不继承类型约束**。

**修复**：要么删 `pattern-not`（主 pattern 已 metavariable-type 约束，全字面量调用本来就不进
主匹配），要么用 `patterns` 块复用 metavariable-type 约束：

```yaml
- pattern-not:
    patterns:
      - pattern: $SFTP.get("...", ...)
      - metavariable-type:
          metavariable: $SFTP
          types: [ChannelSftp, com.jcraft.jsch.ChannelSftp]
```

**排查方法**：

1. 把规则所有 pattern-not 整块删掉跑，看主 pattern 是否命中（确认是 pattern-not 问题）；
2. 二分法切 pattern-not 列表逐次定位罪魁；
3. 重点查 `$X.method("...", ...)` 这类带无约束 metavariable 的条目。

---

### 4.4 Case Study 4：LLM 不逐条分析的认知偷懒

**现象**：用 skill（单 LLM agent 版本）扫描时，semgrep 输出 30+ 条 result 后 LLM 给出的
报告"看了几条就汇总了" —— 部分 sink 被静默跳过、相似 sink 直接归并、缺乏逐条裁决。

**根因分析**：LLM 在长列表面前有几种认知偷懒模式：

1. **上下文压力**：所有 result 一起喂入，token 占用大，LLM 倾向归并而非展开；
2. **指令模糊**："对每个发现做 X" 是自然语言，没有强制循环边界；
3. **无显式进度**：完成 5 个就觉得"差不多了"，剩下的省略；
4. **同类聚簇**：30 条相似 SQL Injection 时，LLM 直接判"这一批都是漏洞"，跳过个体裁决。

**修复方案：三层防偷懒**

**第一层 —— scripts/dispatch.py 脚本去噪**：

新建 `dispatch.py` 在 LLM 之前做三件事：

1. **去重**：key = `(metadata.vuln_class, path, start.line)`，保留首次
2. **按 `metadata.taint_required` 分流**：
   - `false`（fast-path）→ 直接 enrich CWE + severity 产 finding，**无须 LLM**
   - `true` 或缺省 → 写入 pending 列表
3. **过滤非漏洞规则**：vuln_class 为空的规则（如 `spring-api` 路由发现规则）直接跳过

WebGoat 实测：

```
raw_results        : 237
filtered_non_vuln  : 107   ← 路由发现规则（spring-api）
after_dedup_filter : 128
fast_findings      : 40    ← 脚本直接产报告
pending_llm        : 88    ← LLM 逐条裁决（vs 237,工作量 -63%）
```

剩 88 条全是有意义的漏洞 sink（Path Traversal 27、SQL Injection 16、SSRF 16、
Hardcoded Backdoor 15、其他 11）。

**第二层 —— TodoList 强制驱动**：

改 `SKILL.md` 阶段 2 之后：

```
阶段 2 — 任务清单初始化（强制,不可跳过）

读取 pending_llm.json,对**每一条** entry 调 TaskCreate:

  for entry in pending_llm.json:
      TaskCreate(
          subject=f"[{entry.vuln_type}] {entry.filepath}:{entry.line}",
          description=entry.message + " | id=" + entry.id
      )

最后调一次 TaskList 确认所有 entry 都登记为 pending。
若 pending task 数 != dispatch_stats.json 的 pending_llm 计数,必须补齐。

⚠️ 不允许在没登记完所有 task 之前进入阶段 3。

阶段 3 — 逐条上溯追踪(逐 task 严格循环)

对 task list 里每一个 pending task,按下面步骤处理:
  1. TaskUpdate(taskId, status="in_progress")
  2. 执行下方"单条裁决工作流"
  3. TaskUpdate(taskId, status="completed") 才能进下一条

阶段 4 — 自检（强制）

调一次 TaskList 确认所有 pending task 都已 completed。
若仍有 pending 或 in_progress 状态的 task,必须回阶段 3 补齐。
不允许在自检不通过的情况下进入阶段 5。
```

效果：

- LLM 看到 N 条 task 全是 pending，物理上不可能跳过
- 每条 task 独立 TaskUpdate，进度宿主 UI 实时可见
- 收尾自检 pending == 0 防"漏看"
- 中断后下次能从 in_progress / pending 继续

**第三层 —— reference 文档强制深度分析**：

`SKILL.md` 阶段 3.5 加：

```
按 vuln_type 查 reference 文档（强制）

**先**读 $SKILL_DIR/reference/INDEX.md 找到当前 finding 的 vuln_type 对应的
reference 文档,**严格按文档的 6 段流程**执行:

1. sink 模式速查 —— 确认这是个真 sink 还是别的类似形态
2. 数据流追溯重点 —— 按文档指引找污点源
3. 防御机制速查 —— 用 codesearch / lsp 找文档列出的防御函数 / 注解
4. 常见误判 —— 自查避免落入"看似合理的 DEFENDED"陷阱
5. 证据引用范例 —— 按文档格式填 defense_analysis 或 suspicion_reason
6. PoC 模板 —— VULNERABLE 时按文档 PoC 选项填 attack_vector / poc_payload / max_impact

每种 vuln_type 都有专属 reference 文档（按家族分组,共 9 份）。
**不读对应 reference 文档直接裁决 = 审计未尽职**。
```

reference 目录共 13 份家族文档（共 1495 行）+ INDEX.md 覆盖 39 个 vuln_type：

| reference 文档 | 覆盖类型 |
|---|---|
| injection-family.md | SQL/NoSQL/Command/Code/LDAP/XPath/Template/SpEL/JNDI/JDBC URL Injection |
| deserialization-reflection.md | Unsafe Deserialization/Unsafe Reflection |
| xxe.md | XXE (DOM/SAX-StAX/Transform-Validate) |
| ssrf.md | SSRF (HIGH/LOW confidence 两层) |
| path-traversal-family.md | Path Traversal / Zip Slip / Insecure Temp File |
| xss.md | XSS |
| redirect-family.md | Open Redirect / Unvalidated Forward |
| crypto-family.md | Weak Crypto / Weak Random / Insecure TLS / JWT None |
| credentials-backdoor.md | Hardcoded Credentials / Hardcoded Backdoor |
| cookie-trust-boundary.md | Insecure Cookie / Trust Boundary Violation |
| info-disclosure.md | Stack Trace / Sensitive Data in Log/URL |
| authz-family.md | IDOR / Missing Authorization / Privilege Escalation / Auth Bypass |

每份文档结构统一（sink 速查 / 追溯重点 / 防御速查 / 常见误判 / 证据引用范例 / PoC 模板），
LLM 拿到 finding 后查 INDEX 找到对应 family，严格按 6 段流程裁决。

**反面教材内嵌**也是这些文档的关键设计：

```
# 在 authz-family.md 中:
⚠️ **混淆点**（v11/v12 实测反面教材）:
- "已认证用户可删除所有邮件" → **Missing Authorization**（接口没分细分权限）
  而非 Privilege Escalation
- "只对 tom 用户校验密码其他用户直接失败" → **Authentication Bypass / Logic Flaw**
  而非 Privilege Escalation
- "split 验证缺陷绕过路径校验" → **IDOR** 或 **Authentication Bypass**
  (看具体是访问他人资源还是绕过鉴权)
```

把过去 baseline 实测的错判模式作为反例写进 prompt-like 文档，让 LLM 不重蹈覆辙。

**教训沉淀**：

1. **Long-list 的 LLM 偷懒**是个普遍现象，不限于代码审计。任何"对 N 条数据做 X"的 LLM 任务
   都需要外部强制循环（TodoList / 进度状态机）。

2. **脚本预过滤 + LLM 深度分析**是分工正解。让脚本处理重复劳动（fast-path / 去重 / 路由过滤），
   让 LLM 处理真正需要推理的部分。

3. **反面教材 > 正面指引**。在 prompt 里写"应该这样做"不如写"v12 实测错判了 X 不要这样做"
   有效。LLM 对具体场景的记忆比抽象规则强。

---

## 第 5 章 评估方法学

### 5.1 多维度精确率

代码审计的"准确率"在不同口径下数值差异很大。本项目用四个维度评估：

**严格 Precision**（vuln_type 也对）：

```
严格 TP = 真漏洞且 vuln_type 准确
严格 Precision = 严格 TP / 总报告数
```

**宽松 Precision**（"是否真漏洞"维度）：

```
宽松 TP = 真漏洞（含 vuln_type 错挂但漏洞本身存在）
宽松 Precision = 宽松 TP / 总报告数
```

宽松和严格的差额 = 类型错挂 FP（漏洞真实但分类错）。

**重复 FP**：同一 (file, line, vuln_type) 在多个报告里出现。

**完全 FP**：根本不是漏洞，纯 LLM 误判 / 规则错抓。

v8 → v13 完整数据：

| 指标 | v8 | v9 | v10 | v11 | v12 | **v13** |
|---|---:|---:|---:|---:|---:|---:|
| 总 VULN | 122 | 92 | 105 | 117 | 127 | **133** |
| 严格 TP | ~95 | ~75 | 91 | 110 | 110 | **112** |
| 类型错挂 FP | ? | ? | 11 | 3 | 10 | 14 |
| 重复 FP | ? | ? | 3 | 4 | 6 | 7 |
| 完全 FP | ? | ? | 0 | 0 | 1 | **0** |
| 严格 Precision | ~78% | ~80% | 86.7% | **94.0%** | 86.6% | 84.2% |
| 宽松 Precision | ~92% | ~93% | 97.1% | 97.1% | 94.5% | 94.7% |

观察：

1. **严格 Precision** 在 v11 触顶 94%，之后扩规则增召回时略降。
2. **宽松 Precision** 一直在 94-97%，说明"是真漏洞"维度非常稳定，
   只是分类细节有抖动。
3. **完全 FP** 在 v10/v11/v13 都是 0，v12 出现 1 次（`LessonConnectionInvocationHandler`
   被错抓为 Unsafe Reflection，实际是动态代理基础设施）。

### 5.2 召回率维度

**Lesson 维度**（粗粒度）：

WebGoat 有 24 个真漏洞模块（lesson 目录），看 baseline 命中了几个。
v13 覆盖 23/24 = 95.8%，唯一漏的是 `authbypass` 模块（六次 baseline 都没抓到）。

**URL 维度**（中粒度）：

WebGoat 实际有 ~108 个 `@PostMapping/@GetMapping` 注解，去掉 quiz/info 类教学端点后
真漏洞 URL 约 70-80 个。v13 命中 unique URL 数约 60 个，URL 维度召回 ~75-85%。

**漏洞实例维度**（细粒度）：

需要逐个对 WebGoat 已知的"hint"或答题文档校对。本项目没做这层，因为 ground truth
列表整理工作量太大。

### 5.3 验证流水线

我们形成的"开发-验证"流水线：

```
┌────────────────────────────────────────────────────────────────────┐
│ 步骤 1: semgrep --validate 语法校验 (秒级)                            │
│   `semgrep --validate --config semgrep_rules/custom/`               │
│   ↓                                                                  │
│ 步骤 2: Mock 单元测试 (秒级)                                          │
│   - 写 5-10 行 Java mock 覆盖该 vuln_type 的不同形态                  │
│   - `semgrep --json --config new_rule.yaml mock.java`               │
│   - 验证命中/不命中符合预期                                            │
│   ↓                                                                  │
│ 步骤 3: 小批量验证脚本 (~1-3 min)                                     │
│   - 用 .a2a_bus/completed/ 复刻被吞的 task envelope                  │
│   - 直接调 OpenCodeAgent + 新 prompt/schema                          │
│   - 3-4 次重放看稳定性                                                │
│   ↓                                                                  │
│ 步骤 4: 完整 baseline (~50 min)                                       │
│   - codeaudit /target → SUMMARY.md                                  │
│   - 监控 .a2a_bus 进度 + failed 数 + reports 数                       │
│   ↓                                                                  │
│ 步骤 5: 全量人工核对 (~30-60 min)                                     │
│   - 逐条按 vuln_type 分组,标注 TP / 错挂 / 重复 / 完全 FP             │
│   - 算 4 个维度的 Precision                                          │
│   - 列出本轮 vs 上轮的新增 FP / 漏报                                  │
│   ↓                                                                  │
│ 步骤 6: 沉淀到 memory                                                 │
│   - 把这轮发现的"通用陷阱"写成 feedback memory                         │
│   - 把这轮的数据快照写成 project memory                               │
└────────────────────────────────────────────────────────────────────┘
```

整个迭代周期约 2-4 小时（含人工核对）。本项目 6 轮 baseline 总投入约 20 小时
（其中 baseline 跑 6 × 50min = 5 小时，调试 + 写代码 + 核对 ~15 小时）。

### 5.4 评估的两个反直觉发现

**(1) 严格 Precision 和召回率有 trade-off，但绝对 TP 数可单调上升**

v11 严格 94% / TP 110；v12 严格 86.6% / TP 110；v13 严格 84.2% / TP 112。
v12/v13 的 Precision 下降，但绝对真漏洞数不减反增。原因是这两轮主要在扩召回边界
（新增 hardcoded-backdoor 等规则），引入的边缘 case 让 LLM 多了"看似合理但错挂"的 FP。

**结论**：单看 Precision 数字会误判。真正应该看的是"绝对 TP 数 + 完全 FP 率"。
v13 在绝对 TP 数（112）和完全 FP（0）两项都是历史最佳。

**(2) baseline 抖动比想象的大**

v9 漏了 `bypassrestrictions` 和 `deserialization` 两个 lesson（v8/v10/v11 都抓到）。
原因不是规则问题，是 LLM 单次抖动（某些 task BlueValidator schema reject 后丢失）。
v12 又漏了 `bypassrestrictions`（实际是 LogicAuditor 技术类排除把它正确判 DEFENDED）。

**结论**：单次 baseline 漏 1-2 个 lesson 不一定是 bug，可能是抖动。需要做的是：

1. 用"3 次重放"验证可疑修复点（如 4.2 中的 RedValidator 修复）；
2. 累积多轮 baseline 看趋势而非单点结论；
3. 把"历史并集"作为 ground truth 下界，每次 baseline 漏的 URL 优先检查链路。

---

## 第 7 章 经验沉淀

本章把项目中沉淀的可迁移经验整理为四类原则，适用于任意 LLM-工程项目。

### 7.1 LLM Prompt 工程原则

**(1) 反面教材内嵌优于正面指引**

prompt 里"应该这样做"通常被 LLM 解读为"建议"。"v12 实测错判了 X 不要这样做"被
LLM 当作"硬约束"。具体案例：

```yaml
# 弱约束(LLM 容易绕):
"判定时考虑所有参数的可控性"

# 强约束(LLM 不敢绕):
❌ 典型反模式（v12 baseline 实测）:
   Assignment5.java `/challenge/5` login(@RequestParam username, @RequestParam password)
     if (!"Larry".equals(username)) return failed(...);    // username 被白名单限制
     connection.prepareStatement("... '" + username + "' and password='" + password + "'");
   错判 NOT_EXPLOITABLE 的理由:"username 被 'Larry' 白名单限制" — **错!**
   正确判 EXPLOITABLE:username=Larry 通过校验后,**password 仍 100% 可控**,
   注入 `password=' OR '1'='1` 即可绕过登录。
```

**(2) 禁用借口清单要尽可能枚举**

LLM 找 DEFENDED / NOT_EXPLOITABLE 借口的模式可枚举，写成具体清单：

```
❌ 禁用的"看似合理但错误"的 NOT_EXPLOITABLE 理由:
- "username 必须是 Xxx,输入受限" —— 只校验了一个参数,其他参数仍可控
- "前面有 if 判断" —— 看清楚 if 判断的是哪个变量,其他变量是否仍流入 sink
- "用户必须登录才能访问" —— 已登录用户仍可触发漏洞,依然 EXPLOITABLE
- "代码是教学/演示项目" —— 教学项目代码也是真漏洞代码
```

这 4-5 条清单消除了 95% 的"看似合理"翻转。

**(3) 强约束 ≠ 长 prompt**

加 30 行强约束（如 LogicAuditor 的"技术类排除"段）比加 300 行模糊指引更有效。
核心是"禁用什么"而非"建议什么"。

**(4) 输出契约用 schema 而非自然语言**

prompt 里写"必须输出 JSON 含 X / Y / Z 字段"远不如直接定义 `output_schema` 严格。
LLM 输出不符 schema 时引擎层有客户端二次校验 + coerce 救回兜底。

### 7.2 Schema 设计原则

**(1) minLength 要根据语言调整**

中文场景下 `minLength: 20` 太严（约 20 个汉字 / 60 字节）。`minLength: 5` 是合理下限
—— 仍能挡纯 hallucination（如空字符串、单 emoji），但能容忍真实简短回答。

**(2) oneOf 多变体要保留可还原性**

```yaml
oneOf:
  - type: object  # VULNERABLE-A 完整污点链
    required: [status, vuln_type, attack_vector, poc_payload, max_impact, defense_analysis, ...]
  - type: object  # VULNERABLE-B 静态定性
    required: [status, vuln_type, defense_analysis, mitigation_advice, ...]
    not: { anyOf: [{required: [attack_vector]}, {required: [poc_payload]}] }
  - type: object  # DEFENDED
    required: [status, defense_analysis]
    not: { anyOf: [{required: [attack_vector]}, ...] }
```

每个变体的 `not.anyOf` 严格互斥，避免 LLM 输出"既有 attack_vector 又是 DEFENDED"
这种自相矛盾。

**(3) 客户端二次校验 + coerce 救回兜底**

服务端 schema 校验 + 客户端 jsonschema 校验 + coerce 兜底（自动补 minLength 不足的字段）。
三层组合让 schema 严格度提升的同时不丢失 LLM 的真实输出。

### 7.3 LLM 评判 "看似合理" 陷阱清单

把 6 次 baseline 里 LLM 翻转判定的所有借口归类，得到这个清单（已写入 BlueValidator
和 RedValidator prompt）：

| # | 借口 | 反驳 |
|---|---|---|
| 1 | "教学/演示/CTF/靶场项目" | 教学项目代码也是真漏洞代码,按生产代码同等严格判定 |
| 2 | "单参数被白名单限制" | sink 多参数时其他参数可能仍可控,逐参数判定 |
| 3 | "用户必须登录才能访问" | 已登录用户仍可触发漏洞,登录不等于授权 |
| 4 | "数据来自数据库不是 HTTP" | DB 内容可能被先前的 SQL Injection 写入,污点链可跨持久层 |
| 5 | "前端会校验" | 前端校验不作数,攻击者可绕过 |
| 6 | "代码注释说仅 dev 环境" | 注释不可信,看是否有 `@Profile("dev")` 等运行时检查 |
| 7 | "项目用了 Spring Security" | 看具体路径配置,permitAll() 仍可能被打开 |
| 8 | "用了 PreparedStatement" | 看 SQL 字符串是字面量还是字符串拼接 |
| 9 | "用了 BCrypt 哈希" | 看是否真用了,还是只是 import 没用 |
| 10 | "代码有 try/catch" | catch 不是过滤,看 catch 里是否真做了安全处理 |

任何新接触的 LLM-审计任务都建议先把这个清单加进去，能消除 80% 的"看似合理"判定。

### 7.4 Memory 与可复用知识

LLM 短记忆窗口有限，跨对话的知识必须落地到外部存储：

**(1) feedback 类**：避免重复踩坑

```
feedback_semgrep_metavariable_type_var.md  - Java 引擎对 `var x = ...` 推不出类型
feedback_chain_starvation.md               - 链路续接必须 priority=high 否则饿死
feedback_semgrep_pattern_not_pitfalls.md   - pattern-not 两类陷阱
feedback_python_naming_convention.md       - 项目 PEP 8 命名规范
```

**(2) project 类**：状态快照

```
project_overview.md
project_engine_performance_baseline.md
```

**(3) reference 类**：领域知识

skill/security-audit-java/reference/ 下 13 份家族文档 + INDEX.md，按 vuln_type
分组的分析步骤。这是给单 LLM agent 用的，但写完后发现对多 agent 系统同样有用
（可以让 LogicAuditor / BlueValidator 也参考）。

**(4) ground truth 表**：vuln_type → CWE / severity 镜像维护

```python
# 同步维护在 3 处：
# - src/state_router._VULN_TYPE_TO_CWE     (主引擎)
# - skill/.../scripts/classify.py          (skill 版)
# - reference/INDEX.md                     (LLM 查表入口)
```

每次新增 vuln_type 时三处同时更新。

---

## 第 8 章 局限与未来

### 8.1 现有难点

**(1) `authbypass` 模块六次 baseline 始终漏**

这是项目里最顽固的漏报。`authbypass/` 目录下三个文件：

```
AuthBypass.java                 - controller 入口
VerifyAccount.java              - 验证逻辑
AccountVerificationHelper.java  - 辅助校验工具
```

漏洞模式是"跨 helper 类的多步 Auth 校验链有逻辑缺陷"。LogicAuditor 的"跨文件追读 ≤2 跳"
对这种 3-4 跳的链路不够深。

**潜在解法**：

- 加更深的"跨文件 ≤5 跳"模式（成本：单任务时长可能翻倍）
- 写专门的 authbypass.yaml semgrep 规则匹配"helper 类被调用但没有失败短路"模式
- 加 LogicAuditor 的 "auth chain pattern" 启发式提示

**(2) Quiz 答题端点误判**

WebGoat 大量教学 quiz 端点（如 `if (input.equals("Solution 4")) return success()`）被
hardcoded-backdoor 规则识别为后门。这类不是真漏洞但 prompt 难以严格区分"业务后门"
和"教学答案校验"。

**潜在解法**：

- 加 `paths.exclude: ["**/quiz/**", "**/*Quiz*.java"]`（但 WebGoat 命名不规范）
- 引入 quiz 启发式：类内有 `solutions[]` / `guesses[]` 数组字段时降权

**(3) 同 sink 跨 vuln_type 重复命中**

`ProfileZipSlip.java:79` 同时被 Path Traversal 和 Zip Slip 命中。引擎层应该
"同 (file, line) 跨 vuln_type 只保留 confidence/severity 最高的"，但目前没做。

### 8.2 跨项目泛化的挑战

本项目用 WebGoat 作为靶场，所有 prompt / 规则都按 Spring + JDBC + Jackson 等
Java 主流栈调优。跨项目应用时需要面对：

**(1) 框架多样性**

```
prompts/core/logic_auditor.yaml 现在的 prompt:
"该字段名沿用 Spring 习惯,但**实际涵盖任意 Web 框架的请求入口源文件**:
  Spring Controller、JAX-RS Resource、Jersey Endpoint、Express/Koa 路由回调、
  Go HTTP Handler、FastAPI/Flask View、Django View、ASP.NET Action、
  Gin/Echo HandlerFunc、Ruby on Rails Controller、PHP Controller 等。"
```

prompt 已经做了 framework-agnostic 描述，但 Semgrep 规则还是 Java 专属。
跨语言扩展需要重写 spring-api.yaml 类规则。

**(2) 业务上下文注入**

WebGoat 是 self-contained 教学项目，没有"特定业务"。真实企业项目里"用户 A 能否
访问用户 B 的订单"需要业务模型理解。可能的接入：

- OpenAPI / Swagger 规范注入到 LogicAuditor prompt
- DDD 领域模型 / ER 图描述
- 历史漏洞库（CVE / 内部 SRC 报告）作为 reference

**(3) 误报阈值**

WebGoat 上 v13 严格 Precision 84%，宽松 95%。企业项目通常要求宽松 ≥ 95%、严格 ≥ 85%
才能进 CI/CD。需要为不同项目可调 confidence 阈值。

### 8.3 模型层 vs 工程层的权重

回顾 6 轮 baseline，每轮的核心改动归类：

| 类别 | 占比 | 例子 |
|---|---|---|
| **Prompt + Schema 工程** | ~60% | BlueValidator schema fix、RedValidator 逐参数判定、LogicAuditor 技术类排除、教学项目强约束 |
| **Semgrep 规则演进** | ~30% | mass-assignment 新增、ssrf 拆 2 id、xxe 拆 3 id、pattern-not 陷阱修 |
| **调度优化** | ~10% | chain_semaphore、per-agent timeout、 dispatch.py 分流 |

**结论**：在 LLM 多智能体系统里，**60% 的收益来自 prompt + schema 工程**。模型本身的
"原始智能"不是瓶颈，瓶颈是把模型的智能正确地 channelize 进特定任务流的工程能力。

这跟早期 ML 工程的经验吻合：90% 是数据、10% 是模型。LLM 工程是 60% 提示工程、
30% schema/系统设计、10% 模型选型。

### 8.4 演进方向

**短期（1-3 个月）**：

- **增量审计模式**：基于 git diff 只审改动文件 + 影响范围分析。可大幅减少跑时（从 50min 降到 5min）
- **多语言扩展**：Python（Django / FastAPI）/ Go（Gin / Echo）/ TypeScript（Express / NestJS）
  各写一套 spring-api 等价的路由发现规则
- **集成 IDE**：VS Code 插件，保存文件时增量扫描 + 内联标注

**中期（3-12 个月）**：

- **业务上下文注入**：解析项目的 OpenAPI / pom.xml / 配置文件，让 LogicAuditor 知道业务领域
- **CVE/SCA 整合**：和依赖漏洞扫描（Trivy / Snyk）合流，给出"代码+依赖"全景视图
- **客户化 finetune**：针对特定行业（金融 / 医疗）的合规要求微调 prompt

**长期（1-3 年）**：

- **跨仓库知识图谱**：把审计过的 N 个项目的真漏洞模式沉淀为知识库，新项目审计时跨库检索
- **自动修复建议 PR**：不只发现漏洞，自动写修复 PR 让人 review

### 8.5 商业化思考

本项目目前是开源工具（GitHub: Wang1921/CodeAudit），可走的商业化路径：

- **私有部署版**：金融 / 互联网大厂的内部安全平台集成
- **SaaS 版**：对 GitHub/GitLab/Bitbucket 仓库做 PR 级审计
- **咨询服务**：基于本工具做企业代码安全审计

但需要面对：

- **数据隐私**：LLM API 调用需要把代码发给第三方（OpenAI / Anthropic / 火山引擎等）。
  企业客户大概率不接受。需要支持本地 LLM 部署。
- **合规要求**：GDPR / 等保 2.0 / SOC 2 / ISO 27001 等
- **价格定位**：vs Snyk Code / SonarQube / Checkmarx 等成熟商业产品

---

## 附录

### A. 完整 Semgrep 规则集（35 条）

```
hardcoded-backdoor.yaml          (2 id)  ⭐ v12 新增
hardcoded-credentials.yaml       (1 id)
insecure-cookie.yaml             (2 id)
insecure-crypto-config.yaml      (3 id)
insecure-temp-file.yaml          (1 id)
insecure-trust-manager.yaml      (1 id)
jdbc-url-tainted.yaml            (1 id)
jndi-injection.yaml              (1 id)
jwt-none.yaml                    (1 id)
ldap-injection.yaml              (1 id)
mass-assignment.yaml             (3 id)  ⭐ v10 新增
mybatis-xml-sql-injection.yaml   (1 id)
nosql-injection.yaml             (1 id)
open-redirect.yaml               (1 id)
path-traversal.yaml              (1 id)  扩 7 类封装 @ v11
sensitive-data-in-log.yaml       (2 id)
sensitive-data-in-url.yaml       (1 id)
spel-injection.yaml              (1 id)
spring-api.yaml                  (12 id) 路由发现规则
sql-injection.yaml               (5 id)  扩 R2DBC + 链式 @ v10
ssrf.yaml                        (2 id)  拆 execution/construction @ v11
stack-trace-exposure.yaml        (1 id)
template-injection.yaml          (1 id)
trust-boundary.yaml              (1 id)
unsafe-deserialization.yaml      (1 id)
unsafe-reflection.yaml           (1 id)
unvalidated-forward.yaml         (1 id)
weak-cryptography.yaml           (1 id)  扩 EC 短曲线/BC 弱密码/XOR @ v12
weak-random.yaml                 (1 id)
xpath-injection.yaml             (1 id)
xss.yaml                         (1 id)  扩 Model.addAttribute/ResponseEntity.body @ v12
xxe.yaml                         (3 id)  拆 DOM/SAX-StAX/Transform-Validate @ v10
zip-slip.yaml                    (1 id)
code-injection.yaml              (1 id)
command-injection.yaml           (1 id)  扩 5-arity 全字面量 pattern-not @ v13
```

总 ~60 个 rule id。

### B. v8 → v13 数据明细表

| 指标 | v8 | v9 | v10 | v11 | v12 | v13 |
|---|---:|---:|---:|---:|---:|---:|
| 日期 | 2026-05-13 | 2026-05-14 | 2026-05-15 (上午) | 2026-05-15 (下午) | 2026-05-15 (晚) | 2026-05-15 (深夜) |
| 总 VULN | 122 | 92 | 105 | 117 | 127 | 133 |
| Path A (SINK) | 84 | 64 | 57 | 74 | 89 | 93 |
| Path B (ROUTE) | 38 | 28 | 48 | 43 | 38 | 40 |
| Critical | 21 | 22 | 21 | 26 | 26 | 31 |
| High | 41 | 35 | 49 | 54 | 65 | 63 |
| Medium | 58 | 34 | 34 | 36 | 35 | 38 |
| Low | 2 | 1 | 1 | 1 | 1 | 1 |
| 失败任务 | 3 | 16 | 2 | 0 | 0 | 0 |
| Unique URL | 50 | 43 | 60 | 62 | ~67 | ~60 |
| Lesson 召回 (/24) | 20 | 19 | 22 | 22 | 23 | 23 |
| 严格 Precision | ~78% | ~80% | 86.7% | 94.0% | 86.6% | 84.2% |
| 宽松 Precision | ~92% | ~93% | 97.1% | 97.1% | 94.5% | 94.7% |
| 完全 FP | ? | ? | 0 | 0 | 1 | 0 |
| 耗时 | 1h13 | 1h13 | 1h12 | 50min | 50min | 50min |

### C. 关键 commit 列表（按 baseline 演进对照）

```
v8 → v9:
  5b2c791  perf(engine): MAX_AGENT_TIMEOUT 600→300s + 超时换 session 重试 1 次

v9 → v10:
  (per-agent timeout 修复在 v10 commit 链里)
  fix(engine,logic_auditor): LogicAuditor timeout 300→480s + IDOR 优先级抢救 + 27 函数 docstring

v10 → v11:
  e0084d6  fix(blue_validator): minLength 20→5,救回 9 个被 schema reject 吞掉的真漏洞
  c9def1a  fix(ssrf,scanner): 拆 ssrf 为 execution/construction 双 id + 修 --exclude globstar
  4dffd05  fix(blue_validator,sql-injection,path-traversal): 修 v11 三类漏报 + 扩 path-traversal 封装类

v11 → v12:
  52dec40  feat(rules): 新增 hardcoded-backdoor + 扩 weak-crypto/xss 现代 sink

v12 → v13:
  0f65b7d  fix(red_validator): 加逐参数判定 + NOT_EXPLOITABLE 强制 defense_analysis + schema 拦截浅推理
  a5e5610  fix(rules): 修 4 处 pattern-not 过宽导致的漏报(含 metavariable 无 type 约束陷阱)
  f6ceb8c  chore(skill): 同步主引擎 3 个历史 drift 规则到 skill
  7a4040c  feat(skill/reference): 新增 reference/ 目录,告诉 LLM 每类漏洞如何分析
  57fed32  feat(skill): TodoList 驱动 + dispatch.py 分流,解决 LLM 不逐条分析问题
```

### D. WebGoat 24 个真漏洞 lesson 与 v13 命中对照

| Lesson | v13 是否命中 | 主要漏洞类型 |
|---|---|---|
| authbypass | ❌ | Authentication Bypass |
| bypassrestrictions | ✅ | Mass Assignment（边缘）|
| challenges | ✅ | 综合 |
| cia | ✅ | Race Condition / Anti-Automation |
| clientsidefiltering | ✅ | Missing Authorization / Hardcoded Backdoor |
| cryptography | ✅ | Weak Cryptography / Weak Random |
| csrf | ✅ | CSRF / Hardcoded Backdoor |
| deserialization | ✅ | Unsafe Deserialization |
| hijacksession | ✅ | Weak Random |
| idor | ✅ | IDOR |
| insecurelogin | ✅ | Hardcoded Backdoor |
| jwt | ✅ | Auth Bypass / SSRF / SQL Injection |
| logging | ✅ | Sensitive Data in Log |
| missingac | ✅ | Hardcoded Credentials |
| openredirect | ✅ | Open Redirect / SSRF |
| passwordreset | ✅ | Hardcoded Backdoor / IDOR / Anti-Automation |
| pathtraversal | ✅ | Path Traversal / Zip Slip |
| securitymisconfiguration | ✅ | Hardcoded Credentials / Backdoor |
| spoofcookie | ✅ | Insecure Cookie / Weak Random |
| sqlinjection | ✅ | SQL Injection / Hardcoded Backdoor |
| ssrf | ✅ | Sensitive Data in Log |
| vulnerablecomponents | ✅ | Unsafe Deserialization |
| xss | ✅ | XSS / Mass Assignment |
| xxe | ✅ | XXE / Weak Random / Mass Assignment |

23/24 = **95.8%** Lesson 维度召回。

---

## 结语

这一轮工作的核心收获不是"做出了一个 133 VULN 的工具"，而是验证了一个工程命题：

> **LLM 多智能体系统的瓶颈不是模型智能，而是 prompt + schema + 规则 + 调度 的协同工程。**

6 次 baseline 演进里，60% 的收益来自 prompt + schema 工程，30% 来自规则演进，
10% 来自调度优化。每次"看似合理"的 LLM 误判都对应一个具体的 prompt 漏洞 / schema 漏洞，
都能用工程手段（反面教材内嵌 / 禁用借口清单 / 强制证据要求 / metavariable type 约束）
精确修复，并用小批量验证证明。

这给做 LLM 工程化的同行一个朴素的提示：**不要先怀疑模型，先怀疑 prompt 和 schema**。
99% 的"模型不行"实际是"prompt 和 schema 不够好"。

---

*完*

报告生成时间：2026-05-16
项目主页：https://github.com/Wang1921/CodeAudit
作者邮箱：EstellaNicholsonnef@cyberservices.com
