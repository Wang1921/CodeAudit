# OpenCode Server API 文档分析

## 概述

本文档分析了 OpenCode Server 的两个关键 GET �接口：`/session/status` 和 `/session/:id/message`，详细说明了它们的请求格式、响应结构和用途。

---

## 1. GET /session/status 接口

### 接口概述
- **Operation ID**: `session.status`
- **Summary**: Get session status
- **Description**: 检索所有会话的当前状态，包括活跃、空闲和完成状态。

### 请求格式

#### 请求方法
```
GET /session/status
```

#### 查询参数（可选）

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| `directory` | string | 否 | 目录路径 |
| `workspace` | string | 否 | 工作区路径 |

#### 请求体
无（GET 请求不包含请求体）

#### 请求示例
```bash
curl -X GET "http://127.0.0.1:8888/session/status?directory=/home/user/project"
```

### 响应格式

#### 成功响应 (200 OK)
- **Content-Type**: `application/json`
- **响应体结构**: 对象，键为会话 ID，值为会话状态对象

#### 响应示例
```json
{
  "session1": {
    "type": "idle"
  },
  "session2": {
    "type": "busy"
  },
  "session3": {
    "type": "retry",
    "attempt": 2,
    "message": "Retrying operation",
    "next": 5000
  }
}
```

#### SessionStatus 类型说明

**1. 空闲状态 (idle)**
```json
{
  "type": "idle"
}
```
- 表示会话处于空闲状态，可以接收新的消息请求。

**2. 忙碌状态 (busy)**
```json
{
  "type": "busy"
}
```
- 表示会话正在处理消息请求，暂时无法接收新的消息。

**3. 重试状态 (retry)**
```json
{
  "type": "retry",
  "attempt": 2,
  "message": "Retrying operation",
  "next": 5000
}
```
- `type`: 状态类型为重试
- `attempt`: 当前重试次数
- `message`: 重试原因的描述信息
- `next`: 下次重试的等待时间（毫秒）

#### 错误响应 (400 Bad Request)
```json
{
  "success": false,
  "data": {},
  "errors": [
    {
      "field": "error details"
    }
  ]
}
```

### 接口作用和用途

该接口用于获取所有当前会话的状态信息，主要用途包括：

1. **会话监控**：实时监控所有会话的健康状态
2. **负载均衡**：识别空闲会话以分配新任务
3. **故障检测**：识别处于重试状态的会话，判断是否需要干预
4. **调试和诊断**：快速了解系统当前的会话分布情况
5. **并发控制**：在多任务系统中，确保不会向忙碌的会话发送过多请求

在代码审计系统中，该接口被用于：
- `src/agent.py`: 查询会话状态以确定是否可以继续处理任务
- 监控多个 Agent（ReverseTracer、LogicAuditor、RedValidator、BlueValidator 等）的运行状态

---

## 2. GET /session/{sessionID}/message 接口

### 接口概述
- **Operation ID**: `session.messages`
- **Summary**: Get session messages
- **Description**: 检索会话中的所有消息，包括用户提示和 AI 响应。

### 请求格式

#### 请求方法
```
GET /session/{sessionID}/message
```

#### 路径参数

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| `sessionID` | string | **是** | 会话 ID |

#### 查询参数（可选）

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| `directory` | string | 否 | 目录路径 |
| `workspace` | string | 否 | 工作区路径 |
| `limit` | number | 否 | 限制返回的消息数量 |

#### 请求体
无（GET 请求不包含请求体）

#### 请求示例
```bash
curl -X GET "http://127.0.0.1:8888/session/session123/message?limit=50"
```

### 响应格式

#### 成功响应 (200 OK)
- **Content-Type**: `application/json`
- **响应体结构**: 消息对象数组

#### 响应示例
```json
[
  {
    "info": {
      "id": "msg1",
      "sessionID": "session123",
      "role": "user",
      "time": {
        "created": 1640995200000
      },
      "agent": "default",
      "model": {
        "providerID": "openai",
        "modelID": "gpt-4"
      },
      "format": {},
      "system": "",
      "tools": {},
      "variant": "",
      "summary": {
        "diffs": []
      }
    },
    "parts": [
      {
        "type": "text",
        "text": "Hello, how can I help you?"
      }
    ]
  },
  {
    "info": {
      "id": "msg2",
      "sessionID": "session123",
      "role": "assistant",
      "time": {
        "created": 1640995300000,
        "completed": 1640995400000
      },
      "parentID": "msg1",
      "modelID": "gpt-4",
      "providerID": "openai",
      "mode": "chat",
      "agent": "default",
      "path": {
        "cwd": "/home/user",
        "root": "/home/user/project"
      },
      "cost": 0.05,
      "tokens": {
        "input": 100,
        "output": 200,
        "reasoning": 50,
        "cache": {
          "read": 10,
          "write": 5
        }
      },
      "structured": {},
      "variant": "",
      "finish":获取完整响应后停止响应生成器。"stop",
      "summary": false
    },
    "parts": [
      {
        "type": "text",
        "text": "I'd be happy to help you with your task."
      }
    ]
  }
]
```

#### UserMessage 信息结构
```json
{
  "id": "消息ID",
  "sessionID": "会话ID",
  "role": "user",
  "time": {
    "created": 1640995200000
  },
  "agent": "代理名称",
  "model": {
    "providerID": "提供商ID",
    "modelID": "模型ID"
  },
  "format": {},
  "system": "系统提示词",
  "tools": {},
  "variant": "变体",
  "summary": {
    "title": "摘要标题",
    "body": "摘要内容",
    "diffs": []
  }
}
```

#### AssistantMessage 信息结构
```json
{
  "id": "消息ID",
  "sessionID": "会话ID",
  "role": "assistant",
  "time": {
    "created": 1640995200000,
    "completed": 1640995400000
  },
  "error": {},
  "parentID": "父消息ID",
  "modelID": "模型ID",
  "providerID": "提供商ID",
  "mode": "模式",
  "agent": "代理名称",
  "path": {
    "cwd": "当前工作目录",
    "root": "项目根目录"
  },
  "summary": false,
  "cost": 0.05,
  "tokens": {
    "input": 100,
    "output": 200,
    "reasoning": 50,
    "cache": {
      "read": 10,
      "write": 5
    }
  },
  "structured": {},
  "variant": "变体",
  "finish": "停止原因"
}
```

#### Part 消息部分类型

消息的 `parts` 数组包含多种类型的消息部分：

| 类型 | 说明 |
|------|------|
| `TextPart` | 纯文本内容 |
| `SubtaskPart` | 子任务信息 |
| `ReasoningPart` | LLM 推理过程 |
| `FilePart` | 文件内容 |
| `ToolPart` | 工具调用信息 |
| `StepStartPart` | 步骤开始标记 |
| `StepFinishPart` | 步骤完成标记 |
| `SnapshotPart` | 状态快照 |
| `PatchPart` | 代码补丁 |
| `AgentPart` | 代理调用信息 |
| `RetryPart` | 重试信息 |
| `CompactionPart` | 消息压缩信息 |

#### 错误响应 (400 Bad Request)
```json
{
  "success": false,
  "data": {},
  "errors": [
    {
      "field": "错误详情"
    }
  ]
}
```

#### 错误响应 (404 Not Found)
```json
{
  "name": "NotFoundError",
  "data": {
    "message": "Session not found"
  }
}
```

### 接口作用和用途

该接口用于获取指定会话中的所有消息历史，主要用途包括：

1. **会话历史查看**：获取完整的用户-AI 交互记录
2. **调试和故障排查**：检查之前的消息以理解当前状态
3. **审计和日志**：记录所有交互以进行合规性审计
4. **上下文恢复**：在断线重连后恢复会话上下文
5. **成本追踪**：通过 `tokens` 和 `cost` 字段追踪 LLM 使用成本
6. **性能分析**：通过时间戳分析请求响应时间

在代码审计系统中，该接口被用于：
- `src/agent.py`: 获取会话消息历史以支持断点续传和调试
- Web 前端：实时显示 Agent 的推理过程和工具调用
- 报告生成：提取关键推理步骤和证据

---

## 两个接口的对比

| 特性 | GET /session/status | GET /session/{id}/message |
|------|---------------------|---------------------------|
| **主要功能** | 获取所有会话的状态 | 获取特定会话的所有消息 |
| **路径参数** | 无 | `sessionID` (必填) |
| **查询参数** | `directory`, `workspace` | `directory`, `workspace`, `limit` |
| **响应类型** | 状态对象集合 | 消息数组 |
| **响应大小** | 较小（仅状态信息） | 可能很大（完整消息历史） |
| **实时性要求** | 高（用于监控） | 中等（用于历史查询） |
| **主要用途** | 监控会话状态、负载均衡 | 查看会话历史、调试、审计 |

---

## 实际应用场景

### 场景 1：多任务协调器监控

```python
async def monitor_sessions(server_port):
    """监控所有 Agent 会话状态"""
    url = f"http://127.0.0.1:{server_port}/session/status"
    
    while True:
        response = await fetch(url)
        statuses = json.loads(response)
        
        for session_id, status in statuses.items():
            if status['type'] == 'retry':
                print(f"Session {session_id} is retrying: {status}")
            elif status['type'] == 'idle':
                print(f"Session {session_id} is idle, can assign new task")
        
        await asyncio.sleep(1)
```

### 场景 2：会话历史分析

```python
async def analyze_session(server_port, session_id):
    """分析会话消息历史"""
    url = f"http://127.0.0.1:{server_port}/session/{session_id}/message?limit=100"
    
    response = await fetch(url)
    messages = json.loads(response)
    
    total_tokens = 0
    tool_calls = []
    
    for msg in messages:
        if msg['info']['role'] == 'assistant':
            tokens = msg['info'].get('tokens', {})
            total_tokens += tokens.get('input', 0) + tokens.get('output', 0)
            
            for part in msg['parts']:
                if part['type'] == 'tool':
                    tool_calls.append(part)
    
    print(f"Total tokens used: {total_tokens}")
    print(f"Tool calls: {len(tool_calls)}")
```

---

## 结论

这两个接口是 OpenCode Server 的核心监控和调试接口：

1. **`/session/status`**: 提供轻量级的会话状态查询，适合高频监控和负载均衡
2. **`/session/{id}/message`**: 提供完整的会话历史，适合调试、审计和上下文恢复

在代码审计系统的多智能体架构中，这两个接口共同实现了对 Agent 运行状态的实时监控和历史追溯能力。

---

**文档生成时间**: 2026-03-10
**OpenCode Server 版本**: 1.2.24
