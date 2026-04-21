# 实施总结 - 当前实际状态

> **注意**：本文件历史上记录了一份"队列分组 + Session 监控 + 智能调度"的实施清单，
> 但其中**队列分组 / `_fan_out_coordinator_output` / `service_name` 参数等并未进入主线**。
> 详细落地状态请见 [doc/智能调度实施总结.md](doc/智能调度实施总结.md)。

## 当前已落地的关键能力

| 模块 | 文件 | 关键能力 |
| :--- | :--- | :--- |
| 文件总线 | `src/a2a_bus.py` | tmp + fsync + rename 原子写入；`pending/` `processing/` `completed/` `failed/` `help_req/` 五目录拓扑 |
| 沙盒池 | `src/server_manager.py` | 按 cwd 缓存的 OpenCode HTTP 沙盒；**细粒度锁**（`_dict_lock` 护字典 + per-cwd `_startup_locks` 护启动）；LRU + Session-status idle eviction；`/global/health` 健康检查 |
| 引擎 | `src/engine.py` | `_discover_microservices()` + `SemgrepScanner` 一次性扫描后双轨派发；**沙盒池按微服务数自动扩容**；主循环用 `inflight` 集合追踪扇出协程，空闲 2 轮后**自然退出**；跨微服务接力以 `asyncio.gather` 收敛，`(protocol, target)` Future coalescing 去重 |
| 路由 | `src/state_router.py` | **数据驱动的 `ROUTE_RULES` 表**（替代原 6 个重复方法）；JSON 解析**优先 `structured_output`**，降级 JSON+Markdown 代码块；解析失败/字段缺失即丢弃并写入 Kanban |
| Agent | `src/agent.py` | OpenCode HTTP 客户端；`format.type=json_schema` 向服务端声明结构化输出；失败时 `_retry` 在同 session 内触发修复 |
| 状态 | `src/state_tracker.py` | 内置 HTTP 服务（端口 8080），Vue 看板；轮询线程异常自愈 |
| Prompt | `prompts/core/*.yaml` | 6 份模板：`reverse_tracer / logic_auditor / red_validator / blue_validator / report_generator / retry`；每份附 `output_schema` 由引擎注入 OpenCode server 做 JSON Schema 强校验 |

## 历史变更

- **Coordinator 节点已移除**：原"全局测绘 + 动态追踪策略"职责被 Semgrep 规则替代，
  微服务发现交由 `engine._discover_microservices()`。`Coordinator_Output` 消息类型亦已从
  `a2a_bus.SUPPORTED_MESSAGE_TYPES` 移除。
- **接力追踪 fire-and-forget 已纠正**：`_handle_cross_service_reinstantiation` 现以
  `asyncio.gather(return_exceptions=True)` 等待全部接力 ReverseTracer 完成后再 `mark_completed`。
- **总线写入加固**：`mark_completed`/`write_raw_failed` 改为 tmp + fsync + rename，
  避免崩溃窗口造成半写入或源文件丢失。
- **服务端 JSON Schema 结构化输出**：`agent.execute` 把每个 Agent 的 `output_schema` 作为
  `format={type:json_schema}` 传给 OpenCode，服务端校验通过的 JSON 放在 `structured_output` 字段，
  引擎直接读取，避免旧链路中的启发式字符串解析。
- **异常任务不再泄漏 processing/**：`process_task` 捕获异常后调用 `bus.mark_failed` +
  `tracker.agent_finish`，保证 kanban 可达 100% 且不会在 `processing/` 留下残留。
- **跨服务 Future 缓存无泄漏**：owner 完成（成功或失败）后 `finally` 中无条件 pop 缓存条目，
  follower 通过局部变量持有 Future，不受字典清理影响。
- **`_update_tracker_loop` 不再是孤儿 task**：`run()` 保存引用，`finally` 中 cancel+await。
- **服务目录匹配更健壮**：`_get_service_dir` 归一化为绝对路径后用带分隔符的前缀匹配 +
  最长前缀优先，回退则从文件位置向上爬找构建文件。
- **沙盒池锁粒度细化**（2026-04-21）：原 `get_or_start_server` 整段持单一全局锁，
  20 并发被串行化至 1 路；现拆为 `_dict_lock`（只护 `_servers` 字典）+ 每个 cwd 独立的
  `_startup_locks[cwd]`（串行同目录冷启动，不阻塞其他 cwd）。subprocess 启动 /
  健康检查 / dispose 全部移到锁外。
- **沙盒池容量按微服务数自动扩容**（2026-04-21）：`run()` 在 `_discover_microservices()`
  后把 `max_active_servers` 上调至 `max(5, service_count)`，避免多服务场景反复 LRU 淘汰。
- **主循环自然退出**（2026-04-21）：扇出的 `process_task` 协程入 `inflight: set[Task]`，
  `get_pending_tasks()` 返空 **且** `inflight` 空 连续 2 轮才退出；`finally` 中 gather
  剩余任务（超时 5s 后 cancel）再 `shutdown_all()`。

## 配置参数

```python
# src/engine.py
MAX_CONCURRENT_AGENTS = 20
MAX_AGENT_TIMEOUT = 3600
# 主循环空闲退出门槛（idle_ticks 至少累计 2 次才退出）

# src/server_manager.py（可传入构造参数覆写）
max_active_servers = 5          # 引擎会按 max(5, len(service_route_map)) 动态上调
self._idle_timeout = 60.0       # 所有 session 持续 idle 超过此时长才回收
self.health_check_timeout = 30.0
```

## 已知短板（来自架构评审）

1. ~~主循环无完成检测，需要 Ctrl+C 退出~~ — ✅ 已修复（inflight 追踪 + idle_ticks 自然退出）。
2. 崩溃后 `processing/` 中的任务不会自动复活（`is_fresh_start` 只看目录是否为空，无元数据）。
3. ~~Agent 输出无 JSON Schema 强校验~~ — ✅ 已修复（OpenCode server 侧 `format=json_schema`，
   结果经 `structured_output` 返回；`state_router._extract_parsed` 也以此为权威值）。
4. `state_tracker.py` 539 行职责混合（状态模型 + HTTP server + log handler + session poller +
   报告聚合），建议拆分。
5. `AuditEngine.process_task` 70+ 行 God Method，建议抽 `TaskExecutor`。
6. 文件总线无保留策略：`completed/` 每次运行后累加，无归档或 rotate。
7. `reports/` 用相对路径（`state_router._save_vulnerability_report`），必须从项目根目录启动引擎。
8. Red+Blue 双验证 Agent 翻倍 token 消耗，未评估相对于"单 Validator + self-critique"的增益。
9. 无 sink 幂等 / 增量扫描，每次 `main.py` 会 `rmtree(.a2a_bus)` 全量重跑。

详细分析见架构评审记录。
