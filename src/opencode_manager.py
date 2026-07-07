"""OpenCode Agent 管理器。

池化 OpenCodeAgent 实例，委托 OpenCodeServerManager 管理子进程生命周期。
镜像 ClaudeAgentManager 的接口，让 engine.py 无感知后端差异。
"""
import asyncio
import logging
import time
from typing import Any

from src.agents.base import BaseAgent, BaseAgentManager
from src.opencode_agent import OpenCodeAgent
from src.opencode_server_manager import OpenCodeServerManager

logger = logging.getLogger(__name__)


class OpenCodeAgentManager(BaseAgentManager):
    """管理多个 OpenCode Agent 实例。

    与 ClaudeAgentManager 的差异：
    - 额外持有 OpenCodeServerManager 管子进程
    - get_agent 时先确保 server 已启动，再创建/复用 agent
    - shutdown_all 时先关 agent 再关 server
    """

    def __init__(
        self,
        max_active: int = 5,
        config: "OpenCodeConfig | None" = None,
        model: str | None = None,
        hostname: str | None = None,
        port_start: int | None = None,
        default_timeout: float | None = None,
    ):
        """
        Args:
            max_active: 最大并发 Agent / server 数量
            config: OpenCodeConfig 配置对象（优先级高于下面的单独参数）
            model: 模型标识 providerID/modelID（覆盖 config）
            hostname: server 监听地址（覆盖 config）
            port_start: server 端口分配起始值（覆盖 config）
            default_timeout: 单次请求默认超时（秒，覆盖 config）
        """
        from src.agent_factory import OpenCodeConfig

        cfg = config or OpenCodeConfig()
        self.max_active = max_active
        self.model = model or cfg.model
        self.hostname = hostname or cfg.hostname
        self.default_timeout = default_timeout or cfg.default_timeout

        self.server_manager = OpenCodeServerManager(
            max_active_servers=max_active,
            hostname=self.hostname,
            port_start=port_start or cfg.port_start,
            health_check_timeout=cfg.health_check_timeout,
            idle_timeout=cfg.idle_timeout,
        )

        # cwd -> Agent 实例（HTTP 客户端，轻量）
        self._agents: dict[str, OpenCodeAgent] = {}
        self._last_active: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def get_agent(self, cwd: str) -> BaseAgent:
        """获取或创建 cwd 对应的 Agent（必要时先启动 opencode server）。"""
        # 快路径：已有 agent 实例
        if cwd in self._agents:
            self._last_active[cwd] = time.time()
            # 确保 server 仍健康（server 可能被空闲回收）
            await self.server_manager.get_or_start_server(cwd)
            return self._agents[cwd]

        async with self._lock:
            # 双重检查
            if cwd in self._agents:
                self._last_active[cwd] = time.time()
                return self._agents[cwd]

            # 先启动/获取 server 端口
            port = await self.server_manager.get_or_start_server(cwd)

            # 创建 agent HTTP 客户端
            agent = OpenCodeAgent(
                cwd=cwd,
                port=port,
                hostname=self.hostname,
                model=self.model,
                default_timeout=self.default_timeout,
            )
            self._agents[cwd] = agent
            self._last_active[cwd] = time.time()

        logger.info(f"创建新 OpenCode Agent，cwd={cwd}, port={port}")
        return agent

    async def _evict_oldest_locked(self):
        """驱逐最久未使用的 Agent（调用方须持有 _lock）。"""
        if not self._agents:
            return
        oldest_cwd = min(self._last_active, key=self._last_active.get)
        await self._close_agent(oldest_cwd)
        logger.info(f"驱逐旧 OpenCode Agent，cwd={oldest_cwd}")

    async def _close_agent(self, cwd: str):
        """关闭指定 cwd 的 Agent。不直接关 server，由 server_manager 空闲策略回收。"""
        if cwd in self._agents:
            try:
                await self._agents[cwd].close()
            except Exception as e:
                logger.warning(f"关闭 OpenCode Agent 失败，cwd={cwd}: {e}")
            finally:
                del self._agents[cwd]
                self._last_active.pop(cwd, None)

    async def release_agent(self, cwd: str):
        """释放指定 cwd 的 Agent（可选，Manager 会自动管理）。"""
        pass

    def resize(self, max_active: int):
        """调整最大并发数。引擎按微服务数自动扩容时调用。"""
        self.max_active = max(max_active, self.max_active)
        self.server_manager.max_active_servers = self.max_active
        logger.info(f"OpenCodeAgentManager 扩容至 max_active={self.max_active}")

    async def shutdown_all(self):
        """关闭所有 Agent 和 server。"""
        async with self._lock:
            agent_cws = list(self._agents.keys())
        for cwd in agent_cws:
            await self._close_agent(cwd)
        logger.info(f"已关闭所有 {len(agent_cws)} 个 OpenCode Agent")

        await self.server_manager.shutdown_all()

    async def execute(
        self,
        cwd: str,
        prompt: str,
        allowed_tools: str = "lsp,read,codesearch",
        output_schema: dict | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """便捷方法：获取 Agent 并执行。"""
        agent = await self.get_agent(cwd=cwd)
        result = await agent.execute(
            prompt=prompt,
            allowed_tools=allowed_tools,
            output_schema=output_schema,
            timeout=timeout,
        )
        self._last_active[cwd] = time.time()
        return result

    @property
    def active_count(self) -> int:
        return len(self._agents)

    def get_stats(self) -> dict[str, Any]:
        return {
            "active_count": len(self._agents),
            "max_active": self.max_active,
            "working_dirs": list(self._agents.keys()),
            "server_stats": self.server_manager.get_stats(),
            "backend": "opencode",
        }
