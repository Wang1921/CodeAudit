# OpenCode 服务器 — 结构化输出指南

## 概述

OpenCode 服务器支持通过 JSON Schema 约束 LLM 的输出格式，确保返回数据严格符合预定义的结构。该功能通过 `OutputFormat` 联合类型实现，支持两种模式：

| 模式 | 说明 |
|------|------|
| `text` | 普通文本输出（默认） |
| `json_schema` | 结构化 JSON 输出，需提供 JSON Schema |

---

## API 端点

以下端点的请求体均支持 `format` 字段：

| 方法 | 路径 | 说明 |
|------|------|------|
| `POST` | `/session/{id}/message` | 同步发送消息 |
| `POST` | `/session/{id}/prompt_async` | 异步发送消息 |

---

## 请求格式

在请求体中添加 `format` 字段：

```json
{
  "messageID": "msg_xxx",
  "model": { "providerID": "volcengine", "modelID": "glm-5.2" },
  "format": {
    "type": "json_schema",
    "schema": {
      "type": "object",
      "properties": {
        "name": { "type": "string" },
        "age": { "type": "integer" }
      },
      "required": ["name", "age"]
    }
  },
  "parts": [{ "type": "text", "text": "生成一个虚构人物" }]
}
```

### `format` 字段说明

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `type` | `string` | 是 | 固定值 `"json_schema"` |
| `schema` | `object` | 是 | 标准 JSON Schema 文档 |
| `retryCount` | `integer` | 否 | 重试次数（服务端自动管理） |

---

## 响应结构

### 结构化数据位置

LLM 生成的结构化数据位于 `info.structured` 字段：

```json
{
  "info": {
    "id": "msg_xxx",
    "role": "assistant",
    "structured": {
      "name": "张伟",
      "age": 28,
      "skills": ["TypeScript", "React", "Node.js"]
    },
    "error": null
  },
  "parts": [
    { "type": "step-start", "id": "prt_xxx" },
    { "type": "reasoning", "text": "..." },
    {
      "type": "tool",
      "tool": "StructuredOutput",
      "state": {
        "status": "completed",
        "input": { "name": "张伟", "age": 28, "skills": [...] },
        "output": "Structured output captured successfully.",
        "metadata": { "valid": true }
      }
    },
    { "type": "step-finish", "id": "prt_xxx" }
  ]
}
```

### 关键字段

| 字段 | 说明 |
|------|------|
| `info.structured` | 符合 schema 的 JSON 对象（直接使用） |
| `info.error` | 错误信息（结构化输出失败时返回 `StructuredOutputError`） |
| `parts[].tool` (StructuredOutput) | 内部验证结果，`metadata.valid` 表示是否通过 schema 校验 |

---

## 错误处理

当结构化输出失败时，`AssistantMessage.error` 会返回 `StructuredOutputError`：

```json
{
  "name": "StructuredOutputError",
  "data": {
    "message": "输出不符合提供的 JSON Schema",
    "retries": 2
  }
}
```

### 常见错误类型

| 错误类型 | 说明 |
|----------|------|
| `StructuredOutputError` | 输出不符合 schema |
| `ProviderAuthError` | 认证失败 |
| `MessageAbortedError` | 请求被中止 |
| `ContextOverflowError` | 上下文溢出 |
| `APIError` | API 错误 |

---

## Python 示例

```python
import requests
import json
import uuid

BASE = "http://127.0.0.1:4096"

# 创建会话
session = requests.post(f"{BASE}/session", json={}).json()
session_id = session["id"]

# 定义 schema
schema = {
    "type": "object",
    "properties": {
        "name": {"type": "string", "description": "姓名"},
        "age": {"type": "integer", "description": "年龄"},
        "skills": {
            "type": "array",
            "items": {"type": "string"},
            "description": "技能列表"
        }
    },
    "required": ["name", "age", "skills"]
}

# 发送结构化输出请求
payload = {
    "messageID": f"msg{uuid.uuid4().hex[:24]}",
    "model": {"providerID": "volcengine", "modelID": "glm-5.2"},
    "format": {
        "type": "json_schema",
        "schema": schema
    },
    "parts": [{"type": "text", "text": "生成一个虚构的程序员信息"}]
}

resp = requests.post(f"{BASE}/session/{session_id}/message", json=payload, timeout=120)
result = resp.json()

# 获取结构化数据
structured = result["info"]["structured"]
print(json.dumps(structured, indent=2, ensure_ascii=False))

# 验证
from jsonschema import validate
validate(instance=structured, schema=schema)
print("✅ 验证通过")
```

---

## TypeScript 示例

```typescript
const BASE = "http://127.0.0.1:4096";

const schema = {
  type: "object",
  properties: {
    name: { type: "string" },
    age: { type: "integer" },
    skills: { type: "array", items: { type: "string" } },
  },
  required: ["name", "age", "skills"],
};

// 创建会话
const session = await fetch(`${BASE}/session`, { method: "POST" }).then(r => r.json());

// 发送结构化输出请求
const resp = await fetch(`${BASE}/session/${session.id}/message`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    messageID: `msg${crypto.randomUUID().replace(/-/g, "").slice(0, 24)}`,
    model: { providerID: "volcengine", modelID: "glm-5.2" },
    format: { type: "json_schema", schema },
    parts: [{ type: "text", text: "生成一个虚构的程序员信息" }],
  }),
});

const result = await resp.json();
console.log(result.info.structured);
```

---

## 工作原理

1. 客户端在请求中指定 `format.type: "json_schema"` 和 `schema`
2. 服务端将 schema 注入 LLM 的系统提示或工具定义中
3. LLM 生成符合 schema 的 JSON 数据
4. 服务端通过内置的 `StructuredOutput` 工具自动校验输出
5. 校验通过后，数据存储在 `info.structured` 字段返回
6. 校验失败时，返回 `StructuredOutputError` 错误

---

## 注意事项

- `schema` 需符合标准 JSON Schema 规范
- 建议为字段添加 `description` 以提高 LLM 理解准确性
- 复杂嵌套 schema 可能增加 token 消耗
- 不支持流式输出结构化数据
- 模型需支持工具调用（tool calls）功能才能使用结构化输出
