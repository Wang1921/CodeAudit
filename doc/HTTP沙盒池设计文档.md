# HTTP 沙盒池设计文档
**版本**: V2.0  |  **所属子系统**: HTTP 沙盒池管理

> 变更说明（V1.0 → V2.0，2026-04-21）：
> - 锁粒度由"单一全局 `_lock`"拆分为 **`_dict_lock`（护字典）+ per-cwd `_startup_locks`（护冷启动）**，
>   subprocess 启动 / 健康检查 / dispose 全部移出锁外
> - 新增 **Session 状态监控**（`check_idle_servers` / `evict_idle_servers`）
> - 空闲回收阈值 `_idle_timeout` 调整为 **60 秒**（文档 V1.0 曾误记为 600 秒）
> - 池容量由引擎按微服务数 **自动扩容**（`max_active_servers := max(5, len(service_route_map))`）

## 1. 设计目标

管理系统中的多个 OpenCode 服务器实例，实现以下目标：
- 限制并发数量，避免资源耗尽
- 自动健康检查和故障恢复
- LRU + 空闲监控双重回收策略
- 细粒度锁：不同微服务的冷启动互不阻塞，已有 server 的热路径查询不被任何冷启动拖住

## 2. 核心架构

```
┌──────────────────────────────────────────────────┐
│          OpenCodeServerManager                   │
│  ┌────────────────────────────────────────┐     │
│  │ Server Pool (_servers: dict[cwd, Info])│     │
│  │  ┌───────────────────────────────┐     │     │
│  │  │ port: 33043                   │     │     │
│  │  │ cwd: /path/to/service1        │     │     │
│  │  │ process / stderr_task         │     │     │
│  │  │ last_accessed / idle_since    │     │     │
│  │  └───────────────────────────────┘     │     │
│  │  ... (up to max_active_servers)        │     │
│  └────────────────────────────────────────┘     │
│                                                  │
│  Locks:                                          │
│   • _dict_lock          (只护 _servers 字典)     │
│   • _startup_locks[cwd] (per-cwd 启动独占)       │
│                                                  │
│  Public API:                                     │
│   get_or_start_server(cwd) -> port               │
│   check_idle_servers() -> list[cwd]              │
│   evict_idle_servers(force=False) -> int         │
│   shutdown_all()                                 │
└──────────────────────────────────────────────────┘
```

## 3. 核心类

### 3.1 OpenCodeServerManager

**职责**：
- 管理 OpenCode 服务器实例生命周期
- LRU + 空闲监控双重回收
- 自动健康检查
- 进程资源回收

**公有方法**：
| 方法 | 签名 | 说明 |
|------|------|------|
| `get_or_start_server` | `(cwd: str) -> int` | 获取或启动服务器，返回端口；热路径无全局串行 |
| `check_idle_servers` | `() -> List[str]` | 扫描所有 server 的 `/session/status`，返回可回收的 cwd 列表 |
| `evict_idle_servers` | `(force: bool = False) -> int` | 回收一个空闲 server；`force=True` 时即便未到容量上限也回收 |
| `shutdown_all` | `()` | 原子清空字典，并发 dispose 所有进程 |

**内部辅助**：
| 方法 | 说明 |
|------|------|
| `_check_server_health(port)` | 请求 `/global/health`，deadline = 30s 轮询 |
| `_fetch_session_statuses(port)` | 请求 `/session/status` 取全部 session 状态 |
| `_dispose_server_info(info, cwd)` | 只做 stderr_task.cancel + process.terminate/kill，不碰字典 |
| `_evict_oldest_locked()` | **已持 `_dict_lock`** 前提下 pop 最旧条目 |
| `_get_startup_lock(cwd)` | 延迟分配 per-cwd 启动锁 |

## 4. 配置参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `max_active_servers` | 最大并发沙盒数（引擎启动时会上调至 `max(默认, len(service_route_map))`） | 5 |
| `hostname` | 监听主机名 | 127.0.0.1 |
| `cors_origins` | CORS 允许的来源列表 | [] |
| `health_check_timeout` | 启动健康检查总超时（秒） | 30.0 |
| `health_check_interval` | 健康检查重试间隔（秒） | 0.5 |
| `_idle_timeout` | 所有 session 持续 idle 超过此时长才回收（秒） | 60.0 |

## 5. 工作流程

### 5.1 获取或启动服务器（三阶段）

`get_or_start_server(cwd)` 分三阶段设计，最大化并发吞吐：

**Phase 1 — 快路径（短持 `_dict_lock`）**：
1. 字典锁内查找 `cwd` 是否有存活进程
2. 存在 → 更新 `last_accessed`，记录端口
3. 不存在 → 记录需要启动
4. 释放锁

**Phase 2 — 锁外健康检查**：
1. 若 Phase 1 找到端口，在锁外调用 `_check_server_health`
2. 健康 → 直接返回端口
3. 不健康 → 锁内 pop 该条目，锁外 dispose，降级到 Phase 3

**Phase 3 — 慢路径（per-cwd `_startup_locks[cwd]`）**：
1. 获取 cwd 对应的启动锁（不同 cwd 不互斥）
2. 双重检查字典（可能另一协程刚启动成功）
3. 若容量满，**锁内**选出最旧条目 + pop，**锁外** dispose
4. 锁外 `asyncio.create_subprocess_exec` 启动 opencode + 启动 stderr reader
5. 锁外 `_check_server_health` 轮询到绿灯
6. 锁内写回字典

> **为什么这样拆**：原 V1.0 实现整段持一把 `_lock`，20 个并发协程被串行化到 1 路；
> 启动一个 OpenCode 需要 100ms~30s，其他 19 个协程全被阻塞。
> 新实现下，不同 cwd 的冷启动并行；同一个 cwd 的 N 个查询中只有 1 个触发启动，
> 其他 N-1 个看双重检查时已存在，立即返回。

### 5.2 健康检查

- 请求 `GET /global/health`，看响应 JSON 里 `healthy` 字段
- 失败以 `health_check_interval` 轮询，直到 `deadline = now + health_check_timeout`
- 超时即判失败，调用方决定如何处置（启动失败抛 `RuntimeError`，存量不健康则 dispose）

### 5.3 双路径回收策略

**被动回收（容量上限）**：
- `get_or_start_server` 在 Phase 3 发现 `len(_servers) >= max_active_servers`
- 选出 `last_accessed` 最小的 cwd，pop + dispose
- 无条件淘汰，不看是否真的空闲

**主动回收（空闲监控）**：
- `check_idle_servers()` 遍历所有 server，查 `/session/status`
- 所有 session `type=="idle"`（或无 session）→ 记 `idle_since`
- `idle_since` 持续超过 `_idle_timeout` → 加入可回收列表
- 有 session `busy` → 清除 `idle_since` 计时
- `evict_idle_servers(force=True)` 无条件回收最久空闲的一个；
  `force=False` 仅在容量满时回收

### 5.4 崩溃安全的 dispose

`_dispose_server_info(info, cwd)`：
1. `stderr_task.cancel()` + `await`
2. 若 `process.returncode is None`：`terminate()` → `wait(timeout=2.0)` → 超时则 `kill()`
3. 整个过程不持任何锁，允许并发回收多个 server（`shutdown_all` 会用 `asyncio.gather`）

## 6. 使用示例

```python
from src.server_manager import OpenCodeServerManager

server_manager = OpenCodeServerManager(max_active_servers=5)

# 不同 cwd 并发启动会并行，不会互相阻塞
port1, port2 = await asyncio.gather(
    server_manager.get_or_start_server("/path/to/service1"),
    server_manager.get_or_start_server("/path/to/service2"),
)

async with OpenCodeAgent(port=port1) as agent:
    result = await agent.execute(prompt)

# 主循环无任务时可强制回收
await server_manager.evict_idle_servers(force=True)

await server_manager.shutdown_all()
```

## 7. 性能特性

### 7.1 热路径零全局串行
- 已有 server 的 `get_or_start_server` 调用只短持 `_dict_lock` 做字典查找 + 更新时间戳
- 健康检查放在锁外；N 个协程可同时走快路径

### 7.2 冷启动并行
- 不同 cwd 的启动锁互不相同，`asyncio.gather(start_A, start_B, ...)` 真正并行
- 同 cwd 的 N 个并发请求只触发 1 次 `create_subprocess_exec`

### 7.3 容量与项目规模匹配
- `AuditEngine.run()` 在发现微服务后：
  `max_active_servers := max(current, len(service_route_map))`
- 避免 N>5 个微服务时反复 LRU 淘汰

## 8. 错误处理

### 8.1 启动失败
- `_check_server_health` 30s 内未变绿
- 清理刚启动的 process + stderr_task
- 抛 `RuntimeError("服务器启动失败或健康检查超时: {cwd}")`

### 8.2 存量健康检查失败
- `get_or_start_server` 的 Phase 2 发现不健康
- 字典锁内 pop 条目 → 锁外 dispose → 降级到 Phase 3 重启
- 对调用方透明（返回新端口）

### 8.3 dispose 容错
- `_dispose_server_info` 所有操作都 try/except 住，异常只打 debug 日志
- 主流程不会因单个 server 的进程清理异常而卡住
