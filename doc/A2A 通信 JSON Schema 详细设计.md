# 详细设计文档：A2A 通信 JSON Schema 规范

**版本**: V14  |  **所属子系统**: 调度引擎与总线通信

> 变更说明：
> - V7.x: ReportGenerator 下线，改为 Python 字段映射落盘
> - V8.x: ConfigValidator 加入，处理 taint_required=false 的静态配置漏洞
> - V13: ReverseTracer 场景 C 输出 break_reason 替代 defense_analysis
> - V14: 无大变化

## 1. 规范概述

本规范定义了双轨对抗式多智能体代码审计系统中，各个独立 Agent 节点通过文件系统总线（`.a2a_bus`）进行交互的标准数据结构。

所有在系统中流转的 JSON 文件，必须严格遵循本文档定义的"信封 (Envelope) + 载荷 (Payload)"格式。任何破坏格式输出的 Agent 将被引擎拦截并移入死信队列 (`failed/`)。

---

## 2. 基础信封结构 (Base Envelope)

所有的 A2A 消息都必须包含以下最外层的通用属性。

| 字段名 | 数据类型 | 必填 | 描述与枚举值 |
| :--- | :--- | :--- | :--- |
| `a2a_version` | String | 是 | 协议版本，固定为 `"1.0"`。 |
| `message_type` | String | 是 | 消息类型枚举：`TaskRequest`, `VulnCandidate`, `ExploitAttempt`, `ConfirmedVuln`, `CrossServiceTraceRequest`。 |
| `task_id` | String | 是 | 全局唯一的任务追踪 ID（如 `TASK-RT-101`），在整条分析链路中透传，不发生改变。 |
| `sender` | String | 是 | 发送方节点名称（如 `SemgrepScanner`, `ReverseTracer`, `LogicAuditor`, `RedValidator`, `BlueValidator`, `ConfigValidator`）。 |
| `recipient` | String | 是 | 接收方节点名称（如 `ReverseTracer`, `RedValidator`, `Orchestrator`）。 |
| `payload` | Object | 是 | 具体业务载荷，其内部结构由 `message_type` 决定。 |

---

## 3. 业务载荷 Schema 定义 (Payloads)

### 3.1 任务请求 - TaskRequest

**用途**：用于 SemgrepScanner 向执行层派发任务，或 ReverseTracer 向 Orchestrator 发出跨服务追踪请求。

| 字段名 | 数据类型 | 必填 | 描述 |
| :--- | :--- | :--- | :--- |
| `action` | String | 是 | 动作指令：`extract_routes`, `scan_sinks`, `trace_call_chain`, `logic_audit`, `cross_service_trace`, `static_audit`。 |
| `route_details` | Object | 否 | （限 LogicAuditor）包含 `method`, `path`, `handler_file` 等路由信息。 |
| `sink_details` | Object | 否 | （限 ReverseTracer / ConfigValidator）包含 `filepath`, `line_number`, `vuln_class`, `taint_variable`, `taint_required` 等底层触点坐标。 |

**JSON 示例 (逻辑审计任务)**：
```json
{
  "a2a_version": "1.0",
  "message_type": "TaskRequest",
  "task_id": "TASK-LOGIC-001",
  "sender": "SemgrepScanner",
  "recipient": "LogicAuditor",
  "payload": {
    "action": "logic_audit",
    "route_details": {
      "method": "POST",
      "path": "/api/v1/user/update",
      "handler_file": "src/main/java/com/example/controller/UserController.java",
      "handler_line": 35,
      "method_name": "update",
      "owning_service": "user-service"
    }
  }
}
```

**JSON 示例 (逆向追踪任务 - taint_required=true)**：
```json
{
  "a2a_version": "1.0",
  "message_type": "TaskRequest",
  "task_id": "TASK-RT-101",
  "sender": "SemgrepScanner",
  "recipient": "ReverseTracer",
  "payload": {
    "action": "trace_call_chain",
    "sink_details": {
      "vuln_class": "SQL Injection",
      "filepath": "src/main/java/com/example/utils/DbUtil.java",
      "line_number": 45,
      "taint_variable": "sql",
      "taint_required": true
    }
  }
}
```

**JSON 示例 (静态配置任务 - taint_required=false)**：
```json
{
  "a2a_version": "1.0",
  "message_type": "TaskRequest",
  "task_id": "TASK-STATIC-001",
  "sender": "SemgrepScanner",
  "recipient": "ConfigValidator",
  "payload": {
    "action": "static_audit",
    "sink_details": {
      "vuln_class": "Weak Cryptography",
      "filepath": "src/main/java/com/example/utils/CryptoUtil.java",
      "line_number": 23,
      "taint_required": false
    }
  }
}
```

---

### 3.2 疑似漏洞候选 - VulnCandidate

**用途**：由执行层的 `ReverseTracer` 或 `LogicAuditor` 产出，标志着成功连通了内外数据流或发现逻辑缺陷，移交给红队。

**场景 A：成功追踪到外部可控入口**

| 字段名 | 数据类型 | 必填 | 描述 |
| :--- | :--- | :--- | :--- |
| `vuln_type` | String | ��� | 漏洞类型名称（必须从 sink_details.vuln_class 复制）。 |
| `entry_route` | String | 是 | 触发漏洞的顶层 API 入口。 |
| `filepath` | String | 是 | sink 文件路径。 |
| `line_number` | Integer | 是 | sink 行号。 |
| `call_chain` | Array | 是 | 完整的调用链路数组，按执行顺序排列。 |
| `suspicion_reason` | String | 是 | 怀疑存在漏洞的具体原因分析。 |

**场景 B：遇到微服务边界**

| 字段名 | 数据类型 | 必填 | 描述 |
| :--- | :--- | :--- | :--- |
| `action` | String | 是 | 固定为 `cross_service_trace`。 |
| `vuln_type` | String | 是 | 漏洞类型名称。 |
| `protocol` | String | 是 | 协议类型（HTTP / KAFKA / MQ）。 |
| `target_identifier` | String | 是 | 目标标识符（URL 路径或 Topic 名称）。 |
| `taint_variable` | String | 是 | 在边界处接收到的脏数据变量名。 |
| `historical_chain` | Array | 否 | 历史调用链参考。 |

**场景 C：链路断裂**

| 字段名 | 数据类型 | 必填 | 描述 |
| :--- | :--- | :--- | :--- |
| `status` | String | 是 | 固定为 `NOT_EXPLOITABLE`。 |
| `break_reason` | String | 是 | 断裂原因（≥20 字符），说明为何不可利用。 |

**JSON 示例 (场景 A)**：
```json
{
  "vuln_type": "SQL Injection",
  "entry_route": "POST /api/user/login",
  "filepath": "src/main/java/com/example/dao/UserDao.java",
  "line_number": 45,
  "call_chain": [
    "1. UserController.login() — POST /api/user/login, 接收 username 和 password",
    "2. UserService.authenticate() — 调用数据库查询",
    "3. UserDao.findByUsername() — 执行 SQL 查询",
    "4. Connection.prepareStatement() — SQL 拼接 sink"
  ],
  "suspicion_reason": "用户输入直接拼接到 SQL 语句中，未使用参数化查询"
}
```

**JSON 示例 (场景 B)**：
```json
{
  "action": "cross_service_trace",
  "vuln_type": "SQL Injection",
  "protocol": "HTTP",
  "target_identifier": "/api/order/create",
  "taint_variable": "orderData",
  "historical_chain": [
    "1. OrderController.create() — 接收订单数据",
    "2. OrderService.process() — 调用下游服务",
    "3. RestTemplate.postForObject() — 远程调用"
  ]
}
```

**JSON 示例 (场景 C)**：
```json
{
  "status": "NOT_EXPLOITABLE",
  "break_reason": "SQL 语句中的参数来自固定常量数组，非外部���入"
}
```

---

### 3.3 攻击尝试 - ExploitAttempt

**用途**：由 `RedValidator` 产出，表示成功构造了可利用的 Payload，移交给蓝队进行防御核查。

| 字段名 | 数据类型 | 必填 | 描述 |
| :--- | :--- | :--- | :--- |
| `status` | String | 是 | 固定为 `EXPLOITABLE`。 |
| `vuln_type` | String | 是 | 漏洞类型。 |
| `entry_route` | String | 是 | 触发漏洞的 API 入口。 |
| `call_chain` | Array/String | 是 | 调用链路。 |
| `suspicion_reason` | String | 是 | 怀疑存在漏洞的原因。 |
| `attack_vector` | String | 是 | 攻击向量描述。 |
| `poc_payload` | String | 是 | Proof of Concept payload。 |
| `max_impact` | String | 是 | 最大影响描述。 |

---

### 3.4 确认漏洞 - ConfirmedVuln

**用途**：由 `BlueValidator` 或 `ConfigValidator` 产出，表示漏洞已确认，交给报告模块落盘。

| 字段名 | 数据类型 | 必填 | 描述 |
| :--- | :--- | :--- | :--- |
| `status` | String | 是 | 固定为 `VULNERABLE`。 |
| `vuln_type` | String | 是 | 漏洞类型。 |
| `entry_route` | String | 是 | 触发漏洞的 API 入口或 sink 文件路径（静态配置漏洞）。 |
| `call_chain` | Array/String | 是 | 调用链路。 |
| `suspicion_reason` | String | 是 | 怀疑存在漏洞的原因。 |
| `attack_vector` | String | 是 | 攻击向量描述。 |
| `poc_payload` | String | 是 | PoC payload。 |
| `max_impact` | String | 是 | 最大影响。 |
| `defense_analysis` | String | 是 | 防御分析。 |
| `mitigation_advice` | String | 是 | 修复建议。 |

---

### 3.5 跨微服务追踪请求 - CrossServiceTraceRequest

**用途**：由 `ReverseTracer` 产出，遇到微服务边界时向引擎发出跨界追踪请求。

| 字段名 | 数据类型 | 必填 | 描述 |
| :--- | :--- | :--- | :--- |
| `action` | String | 是 | 固定为 `cross_service_trace`。 |
| `vuln_type` | String | 是 | 漏洞类型。 |
| `protocol` | String | 是 | 协议类型。 |
| `target_identifier` | String | 是 | 目标标识符。 |
| `taint_variable` | String | 是 | 脏数据变量名。 |
| `historical_chain` | Array | 否 | 历史调用链。 |

---

## 4. 消息流转拓扑

```
SemgrepScanner
    ├── route → LogicAuditor → RedValidator → BlueValidator → Report
    │                                            └── 场景 B (技术类): 丢弃
    ├── sink (taint_required=true) → ReverseTracer
    │                              ├── 场景 A (成功) → RedValidator → BlueValidator → Report
    │                              ├── 场景 B (跨界) → Engine → 跨服务 ReverseTracer
    │                              └── 场景 C (断裂) → 丢弃
    └── sink (taint_required=false) → ConfigValidator → Report
```

---

## 5. 终止状态

| status | 来源 | 含义 |
|--------|------|------|
| `NOT_EXPLOITABLE` | ReverseTracer / RedValidator | 链路断裂或参数不可控 |
| `DEFENDED` | BlueValidator / ConfigValidator | 存在有效防御机制 |

当 Agent 输出 `status: NOT_EXPLOITABLE` 或 `status: DEFENDED` 时，引擎立即终止该任务链路，不向下游派发。