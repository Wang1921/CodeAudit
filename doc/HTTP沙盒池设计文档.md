# HTTP 沙盒池设计文档
**版本**: V1.0  |  **所属子系统**: HTTP 沙盒池管理

## 1. 设计目标

管理系统中的多个 OpenCode 服务器实例，实现以下目标：
- 限制并发数量，避免资源耗尽
- 自动健康检查和故障恢复
- LRU 缓存策略，优化资源利用

## 2. 核心架构

```
┌──────────────────────────────────────────────────┐
│            OpenCodeServerManager            │
│  ┌────────────────────────────────────┐    │
│  │  Server Pool (LRU Cache)         │    │
│  │  ┌───────────────────────────┐  │    │
│  │  │ port: 33043              │  │    │
│  │  │ cwd: /path/to/service1   │  │    │
│  │  │ last_used: timestamp      │  │    │
│  │  └───────────────────────────┘  │    │
│  │  ┌───────────────────────────┐  │    │
│  │  │ port: 33044              │  │    │
│  │  │ cwd: /path/to/service2   │  │    │
│  │  │ last_used: timestamp      │  │    │
│  │  └───────────────────────────┘  │    │
│  └────────────────────────────────────┘    │
│                                           │
│  get_or_start_server(cwd) -> int        │
│  shutdown_all()                         │
│  _health_check(port)                    │
└──────────────────────────────────────────┘
```

## 3. 核心类

### 3.1 OpenCodeServerManager

**职责**：
- 管理 OpenCode 服务器实例
- 实现 LRU 缓存策略
- 自动健康检查
- 资源回收和清理

**方法**：
| 方法 | 参数 | 返回值 | 说明 |
|------|------|--------|------|
| `__init__` | `max_active_servers` | None | 初始化沙盒池管理器 |
| `get_or_start_server` | `target_cwd: str` | `int` | 获取或启动服务器，返回端口 |
| `shutdown_all` | - | None | 关闭所有服务器 |
| `_health_check` | `port: int` | `bool` | 健康检查 |

## 4. 配置参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `max_active_servers` | 最大并发沙盒数 | 5 |
| `hostname` | 监听主机名 | 127.0.0.1 |
| `cors_origins` | CORS 允许的来源列表 | [] |
| `health_check_timeout` | 健康检查超时(秒) | 30.0 |
| `health_check_interval` | 健康检查重试间隔(秒) | 0.5 |

## 5. 工作流程

### 5.1 获取或启动服务器

1. 检查 `active_servers` 缓存，是否存在匹配 `target_cwd` 的服务器
2. 如果存在，更新 `last_used` 时间戳，返回端口
3. 如果不存在，检查是否达到 `max_active_servers` 上限
4. 如果达到上限，回收最旧的服务器（最少的 `last_used`）
5. 启动新的 OpenCode 服务器
6. 添加到 `active_servers` 缓存
7. 执行健康检查
8. 返回端口

### 5.2 健康检查

1. 发送 `GET /global/health` 请求
2. 检查响应状态码和响应内容
3. 如果失败，重启服务器
4. 重试直到成功或超时

### 5.3 资源回收

1. 找到 `active_servers` 中 `last_used` 最小的服务器
2. 调用 `shutdown` 方法关闭服务器
3. 从缓存中移除
4. 返回端口供重用

## 6. 使用示例

```python
from src.server_manager import OpenCodeServerManager

# 初始化沙盒池管理器
server_manager = OpenCodeServerManager(max_active_servers=5)

# 获取或启动服务器
port1 = await server_manager.get_or_start_server("/path/to/service1")
port2 = await server_manager.get_or_start_server("/path/to/service2")

# 使用服务器（通过 OpenCodeAgent）
async with OpenCodeAgent(port=port1) as agent:
    result = await agent.execute(prompt)

# 关闭所有服务器
await server_manager.shutdown_all()
```

## 7. 性能优化

### 7.1 LRU 缓存策略
- 优先复用最近使用的服务器
- 自动回收最不活跃的服务器

### 7.2 并发控制
- 限制最大并发数，避免资源耗尽
- 达到上限时自动排队或回收

### 7.3 健康检查优化
- 异步健康检查，不阻塞主线程
- 失败自动重启，提高可用性

## 8. 错误处理

### 8.1 启动失败
- 记录错误日志
- 移除无效服务器
- 抛出异常供上层处理

### 8.2 健康检查失败
- 自动重启服务器
- 重试机制（最多 3 次）
- 超时后移除服务器

### 8.3 资源回收失败
- 强制关闭服务器
- 清理缓存
- 记录错误日志

## 9. 监控指标

| 指标 | 说明 |
|------|------|
| `active_servers_count` | 当前活跃服务器数量 |
| `total_servers_created` | 总共创建的服务器数量 |
| `total_servers_destroyed` | 总共销毁的服务器数量 |
| `health_check_failures` | 健康检查失败次数 |
