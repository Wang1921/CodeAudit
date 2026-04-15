# 详细设计文档：A2A 通信 JSON Schema 规范
**版本**: V2.1  |  **所属子系统**: 调度引擎与总线通信

> 变更说明（V2.0 → V2.1）：原 `Coordinator_Output` 消息类型与对应载荷已下线，
> 项目测绘改由引擎自身的 `_discover_microservices()` 与 Semgrep 输出共同承担。
> 当前在线消息类型见 §2 与 `src/a2a_bus.py: SUPPORTED_MESSAGE_TYPES`。

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
| `sender` | String | 是 | 发送方节点名称（如 `SemgrepScanner`, `ReverseTracer`, `LogicAuditor`, `RedValidator`, `BlueValidator`）。 |
| `recipient` | String | 是 | 接收方节点名称（如 `ReverseTracer`, `RedValidator`, `Orchestrator`）。 |
| `payload` | Object | 是 | 具体业务载荷，其内部结构由 `message_type` 决定。 |

---

## 3. 业务载荷 Schema 定义 (Payloads)

> 系统不再产出全局测绘消息。引擎初始化阶段直接调用 `SemgrepScanner.scan()` 取得
> `routes` 与 `sinks`，然后按下一节 `TaskRequest` 形式将每个条目派发到对应 Agent 队列。

### 3.1 任务请求
**用途**：用于 SemgrepScanner 向执行层派发任务，或 ReverseTracer 向 Orchestrator 发出跨服务追踪请求。

**字段说明**：
| 字段名 | 数据类型 | 必填 | 描述 |
| :--- | :--- | :--- | :--- |
| `action` | String | 是 | 动作指令：`extract_routes`, `scan_sinks`, `trace_call_chain`, `logic_audit`, `cross_service_trace`。 |
| `route_details` | Object | 否 | （限 LogicAuditor）包含 `method`, `path`, `handler_file` 等路由信息。 |
| `sink_details` | Object | 否 | （限 ReverseTracer）包含 `filepath`, `line_number`, `dangerous_code`, `taint_variable` 等底层触点坐标。 |
| `tracing_strategy` | String | 否 | （限 ReverseTracer）动态追踪策略。 |

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

**JSON 示例 (逆向追踪任务)**：
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
      "vuln_class": "CWE-409 (Zip Bomb)",
      "filepath": "src/main/java/com/example/utils/ZipUtil.java",
      "line_number": 45,
      "dangerous_code": "if (entry.getSize() > LIMIT)",
      "taint_variable": "entry"
    },
    "tracing_strategy": "在Spring Boot框架中进行动态追踪时，应遵循以下策略..."
  }
}
```

### 3.2 疑似漏洞候选
**用途**：由执行层的 `ReverseTracer` 或 `LogicAuditor` 产出，标志着成功连通了内外数据流或发现逻辑缺陷，移交给红队。

**字段说明**：
| 字段名 | 数据类型 | 必填 | 描述 |
| :--- | :--- | :--- | :--- |
| `vuln_type` | String | 是 | 漏洞类型名称及简述。 |
| `entry_route` | String | 是 | 触发漏洞的顶层 API 入口。 |
| `call_chain` | Array/String | 是 | 完整的调用链路数组，按执行顺序排列。 |
| `suspicion_reason` | String | 是 | 怀疑存在漏洞的具体原因分析。 |

**JSON 示例**：
```json
{
  "a2a_version": "1.0",
  "message_type": "VulnCandidate",
  "task_id": "TASK-RT-101",
  "sender": "LogicAuditor",
  "recipient": "RedValidator",
  "payload": {
    "vuln_type": "IDOR (垂直越权)",
    "entry_route": "POST /api/v1/admin/config",
    "call_chain": [
      "1. AdminController.updateConfig()",
      "2. ConfigService.save()"
    ],
    "suspicion_reason": "updateConfig 方法内未检查当前会话的角色，直接信任并处理了外部输入。"
  }
}
```

### 3.3 攻击推演记录
**用途**：由 `RedValidator` 产出，记录了针对疑似漏洞的具体攻击手段和 Payload，移交给蓝队。

**字段说明**：
| 字段名 | 数据类型 | 必填 | 描述 |
| :--- | :--- | :--- | :--- |
| `status` | String | 是 | 枚举值：EXPLOITABLE (可利用) 或 NOT_EXPLOITABLE (无法利用，触发熔断)。 |
| `vuln_type` | String | 否 | 继承自上一步的漏洞类型。 |
| `entry_route` | String | 否 | 继承自上一步的 API 入口。 |
| `attack_vector` | String | 否 | 攻击手法描述与绕过思路。 |
| `poc_payload` | String | 否 | 具体的 Proof of Concept 请求体或触发参数。 |
| `max_impact` | String | 否 | 漏洞造成的最坏影响评估 (如 RCE, Data Leak)。 |

**JSON 示例**：
```json
{
  "a2a_version": "1.0",
  "message_type": "ExploitAttempt",
  "task_id": "TASK-RT-101",
  "sender": "RedValidator",
  "recipient": "BlueValidator",
  "payload": {
    "status": "EXPLOITABLE",
    "vuln_type": "IDOR (垂直越权)",
    "entry_route": "POST /api/v1/admin/config",
    "attack_vector": "使用普通用户 Token 构造越权请求，修改注册开放开关。",
    "poc_payload": "{\"config_key\": \"allow_public_reg\", \"value\": \"true\"}",
    "max_impact": "High - 普通用户可获取系统最高控制权"
  }
}
```

### 3.4 最终确认漏洞
**用途**：由 `BlueValidator` 产出，标志着防御被红队击穿，正式作为真实漏洞输出至报告系统。

**字段说明**：
| 字段名 | 数据类型 | 必填 | 描述 |
| :--- | :--- | :--- | :--- |
| `status` | String | 是 | 枚举值：VULNERABLE (确认为真实漏洞) 或 DEF (已被拦截，触发熔断)。 |
| `defense_analysis` | String | 否 | 蓝队视角的防御缺失分析（为何现有的 Filter/WAF 没防住红队的 PoC）。 |
| `mitigation_advice` | String | 否 | 针对代码级的修复建议与缓解措施。 |

**JSON 示例**：
```json
{
  "a2a_version": "1.0",
  "message_type": "ConfirmedVuln",
  "task_id": "TASK-RT-101",
  "sender": "BlueValidator",
  "recipient": "ReportGenerator",
  "payload": {
    "status": "VULNERABLE",
    "defense_analysis": "代码库中不存在针对 /api/v1/admin/* 的全局鉴权 Filter，且 Controller 方法上缺乏 @PreAuthorize 注解，防御被击穿。",
    "mitigation_advice": "在 AdminController.updateConfig() 头部增加 requireRole('ADMIN') 强校验，或配置全局拦截器。"
  }
}
```

### 3.5 跨微服务追踪请求
**用途**：由 `ReverseTracer` 发出，当发现微服务边界时，向 Orchestrator 请求跨服务追踪。

**字段说明**：
| 字段名 | 数据类型 | 必填 | 描述 |
| :--- | :--- | :--- | :--- |
| `action` | String | 是 | 固定值 "cross_service_trace"。 |
| `vuln_type` | String | 是 | 漏洞类型。 |
| `protocol` | String | 是 | 通信协议（HTTP/KAFKA/MQ）。 |
| `target_identifier` | String | 是 | 目标标识符（如 Topic 名称或 URL 路径）。 |
| `historical_chain` | Array[String] | 是 | 历史调用链。 |
| `taint_variable` | String | 是 | 污点变量名。 |

**JSON 示例**：
```json
{
  "a2a_version": "1.0",
  "message_type": "CrossServiceTraceRequest",
  "task_id": "TASK-RT-101_CROSS",
  "sender": "ReverseTracer",
  "recipient": "Orchestrator",
  "payload": {
    "action": "cross_service_trace",
    "vuln_type": "SpEL Injection",
    "protocol": "KAFKA/MQ",
    "target_identifier": "eval-requests",
    "historical_chain": [
      "1. 当前服务: KafkaConsumerService.handleEvalRequest(EvalRequest request) @KafkaListener(topics = eval-requests)",
      "2. 当前服务边界入口: request.getExpression() -> evalService.evaluate(expression)"
    ],
    "taint_variable": "request.getExpression()"
  },
  "priority": "high"
}
```
