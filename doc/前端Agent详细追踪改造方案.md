# 前端 Agent 详细追踪改造方案

## 📋 改造背景

### 当前局限性
前端只能看到 Agent 的基础信息：
- `id`, `role`, `task`, `time`, `statusColor`

无法看到：
- Agent 的实时运行状态（busy/idle/retry）
- Agent 的消息历史（用户输入、LLM 响应）
- 工具调用详情（read, grep, lsp, codesearch 等）
- Token 消耗明细
- 推理过程展示

### 改造目标
利用 OpenCode Server 的两个接口：
- `GET /session/status` - 获取会话状态
- `GET /session/:id/message` - 获取会话消息历史

实现 Agent 运行时的详细进展追踪。

---

## 🎯 改造架构

```
┌─────────────────────────────────────────────────────────┐
│                    StateTracker                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │  后台轮询任务 (每 2 秒)                       │   │
│  │  ├─ 查询 /session/status                       │   │
│  │  └─ 查询 /session/:id/message                  │   │
│  └─────────────────────────────────────────────────┘   │
│                      ↓                                  │
│              更新 state.session_registry                 │
└─────────────────────────────────────────────────────────┘
                         ↓
              HTTP 推送到前端 /state.json
                         ↓
┌─────────────────────────────────────────────────────────┐
│              Vue.js 前端渲染                           │
│  ├─ Agent 列表 (基础信息)                             │
│  ├─ Agent 详情面板 (会话状态、消息历史)               │
│  └─ 工具调用时间线                                    │
└─────────────────────────────────────────────────────────┘
```

---

## 📝 详细改造清单

### 1️⃣ 后端改造

#### 文件 1: `src/state_tracker.py`

**新增数据结构**：
在 `__init__` 中的 `state` 字典中添加 `session_registry` 字段。

**新增方法**：
- `track_session()` - 注册新的会话追踪
- `update_sessions_from_opencode()` - 后台任务：从 OpenCode Server 拉取会话状态和消息
- `_fetch_session_status()` - 获取单个会话状态
- `_fetch_session_messages()` - 获取会话消息历史
- `_extract_tool_calls()` - 从消息中提取工具调用记录
- `untrack_session()` - 取消追踪会话
- `_start_session_poller()` - 启动会话状态轮询任务

**关键代码**：
```python
# 在 __init__ 中添加
self.state["session_registry"] = {}

# 后台轮询任务
async def update_sessions_from_opencode(self):
    sessions = self.state["session_registry"].copy()
    for task_id, session_info in sessions.items():
        # 查询会话状态和消息
        status = await self._fetch_session_status(...)
        messages = await self._fetch_session_messages(...)
        tools = self._extract_tool_calls(messages)
        # 更新状态
```

---

#### 文件 2: `src/agent.py`

**改造点**：
1. 在 `_create_session` 方法中调用 `tracker.track_session()`（已有，需确认）
2. 在 `shutdown` 方法中调用 `tracker.untrack_session()`（新增）

**关键代码**：
```python
async def shutdown(self) -> None:
    if self._session_tracker and self._current_task_id:
        self._session_tracker.untrack_session(self._current_task_id)
    # ... 其他清理代码
```

---

#### 文件 3: `src/engine.py`

**改造点**：
在 `process_task` 方法中设置 session tracker。

**关键代码**：
```python
async with OpenCodeAgent(port=port, timeout=MAX_AGENT_TIMEOUT) as agent:
    agent.set_session_tracker(self.tracker)
    agent.set_current_task(env["task_id"])
    result = await agent.execute(prompt, allowed_tools=allowed_tools)
```

---

### 2️⃣ 前端改造

#### 文件 4: `web/index.html`

**改造内容**：
1. 新增 Agent 详情面板（显示会话状态、Token 消耗、工具调用时间线、消息历史）
2. 修改 Agent 列表，添加点击事件
3. 在 Vue setup 中添加相关方法：`selectAgent`, `getSessionStatusColor`, `formatTokens`, `formatTime`
4. 在轮询中更新 `sessionRegistry`

**关键代码**：
```html
<!-- Agent 详情面板 -->
<section v-if="selectedAgent" class="w-2/5 bg-gray-800 rounded-lg border border-gray-700 flex flex-col">
    <!-- 会话状态 -->
    <!-- Token 消耗 -->
    <!-- 工具调用时间线 -->
    <!-- 消息历史 -->
</section>
```

```javascript
const selectedAgent = ref(null);
const sessionRegistry = reactive({});

const selectAgent = (agent) => {
    selectedAgent.value = agent;
    if (sessionRegistry[agent.id]) {
        selectedAgent.value.session_info = sessionRegistry[agent.id];
    }
};
```

---

## 🔄 数据流

```
OpenCode Server                    StateTracker                    前端
     │                                │                           │
     │  GET /session/status            │                           │
     │  ────────────────────────────> │                           │
     │                                │  更新 state.sessions      │
     │                                │  ────────────────────────>│
     │                                │                           │  渲染详情
     │  GET /session/:id/message       │                           │
     │  ────────────────────────────> │                           │
     │                                │  更新消息历史            │
     │                                │  ────────────────────────>│
     │                                │                           │  显示消息
```

---

## ⚠️ 注意事项

### 性能优化
1. **消息查询频率控制**：每 5 秒查询一次消息历史
2. **消息数量限制**：`limit=20` 只获取最近 20 条消息
3. **异步轮询**：使用 `asyncio` 并发查询多个会话
4. **错误容错**：单个会话查询失败不影响其他会话

### 兼容性
1. **向后兼容**：保留原有的 Agent 基础信息展示
2. **优雅降级**：如果 OpenCode Server 不可用，前端显示基础信息

### 资源清理
1. **取消追踪**：Agent 完成任务后及时取消追踪
2. **定时器清理**：避免内存泄漏

---

## 📊 改造后的前端界面效果

```
┌────────────────────────────────────────────────────────────────┐
│  Header                                                      │
├──────────────┬──────────────────────┬─────────────────────────┤
│              │   Agent Details       │                         │
│   Agents     │   ──────────────    │      Kanban             │
│              │   Session Status:    │                         │
│  ● SemgrepSc │   ● busy           │   1. Suspicious         │
│  ● ReverseT  │   Token Usage:      │   2. Red Team          │
│  ● LogicA    │     Total: 1,234   │   3. Blue Team         │
│              │     Input: 500      │   4. Resolved           │
│  [点击查看详情]│     Output: 734     │                         │
│              │   Tool Calls:        │                         │
│              │     → read(...)      │                         │
│              │     → grep(...)     │                         │
│              │   Message History:   │                         │
│              │     User: ...        │                         │
│              │     Assistant: ...   │                         │
└──────────────┴──────────────────────┴─────────────────────────┘
```

---

## 🎯 实施步骤

### 阶段实施
1. **第一阶段**：修改 `src/state_tracker.py` 添加会话追踪功能
2. **第二阶段**：修改 `src/agent.py` 和 `src/engine.py` 集成追踪
3. **第三阶段**：修改 `web/index.html` 添加详情面板和状态展示
4. **第四阶段**：测试并优化性能

### 测试要点
1. 单个 Agent 的状态查询
2. 多个 Agent 并发的状态查询
3. OpenCode Server 不可用时的降级
4. 消息历史解析和展示
5. Token 统计准确性

---

**文档创建时间**: 2026-03-10
**版本**: 1.0
