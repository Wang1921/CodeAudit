# 实施总结 - 当前实际状态

> **注意**：本文件历史上记录了一份"队列分组 + Session 监控 + 智能调度"的实施清单，
> 但其中**队列分组 / `_fan_out_coordinator_output` / `service_name` 参数等并未进入主线**。
> 详细落地状态请见 [doc/智能调度实施总结.md](doc/智能调度实施总结.md)。

## 当前已落地的关键能力

| 模块 | 文件 | 关键能力 |
| :--- | :--- | :--- |
| 文件总线 | `src/a2a_bus.py` | tmp + fsync + rename 原子写入；`pending/` `processing/` `completed/` `failed/` `help_req/` 五目录拓扑 |
| 沙盒池 | `src/server_manager.py` | 按 cwd 缓存的 OpenCode HTTP 沙盒；LRU + Session-status idle eviction；`/global/health` 健康检查 |
| 引擎 | `src/engine.py` | `_discover_microservices()` + `SemgrepScanner` 一次性扫描后双轨派发；跨微服务接力以 `asyncio.gather` 收敛 |
| 路由 | `src/state_router.py` | 统一 next-hop 表 + JSON 解析容错；解析失败/字段缺失即丢弃并写入 Kanban |
| 状态 | `src/state_tracker.py` | 内置 HTTP 服务（端口 8080），Vue 看板；轮询线程异常自愈 |
| Prompt | `prompts/core/*.yaml` | 6 份模板：`reverse_tracer / logic_auditor / red_validator / blue_validator / report_generator / retry` |

## 历史变更

- **Coordinator 节点已移除**：原"全局测绘 + 动态追踪策略"职责被 Semgrep 规则替代，
  微服务发现交由 `engine._discover_microservices()`。`Coordinator_Output` 消息类型亦已从
  `a2a_bus.SUPPORTED_MESSAGE_TYPES` 移除。
- **接力追踪 fire-and-forget 已纠正**：`_handle_cross_service_reinstantiation` 现以
  `asyncio.gather(return_exceptions=True)` 等待全部接力 ReverseTracer 完成后再 `mark_completed`。
- **总线写入加固**：`mark_completed`/`write_raw_failed` 改为 tmp + fsync + rename，
  避免崩溃窗口造成半写入或源文件丢失。

## 配置参数

```python
# src/engine.py
MAX_CONCURRENT_AGENTS = 20
MAX_AGENT_TIMEOUT = 3600

# src/server_manager.py
max_active_servers = 5
self._idle_timeout = 60.0
self.health_check_timeout = 30.0
```

## 已知短板（来自架构评审）

1. 主循环无完成检测，需要 Ctrl+C 退出。
2. 崩溃后 `processing/` 中的任务不会自动复活。
3. Agent 输出无 JSON Schema 强校验（只有启发式解析 + 一次性 retry）。
4. `state_tracker.py` 539 行职责混合，建议拆分。

详细分析见架构评审记录。
