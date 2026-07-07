"""
Claude Agent 会话管理器

管理多个 Claude Code CLI 会话，复用 Agent 实例
"""
import asyncio
import logging
import time
from typing import Any

from src.agents.base import BaseAgent, BaseAgentManager
from src.claude_agent import ClaudeAgent

logger = logging.getLogger(__name__)


class ClaudeAgentManager(BaseAgentManager):
    """管理多个 Claude Code CLI 会话"""

    def __init__(self, max_active: int = 5):
        """
        初始化管理器

        Args:
            max_active: 最大并发 Agent 数量
        """
        self.max_active = max_active

        # cwd -> Agent 实例
        self._agents: dict[str, ClaudeAgent] = {}
        # cwd -> 最后活跃时间
        self._last_active: dict[str, float] = {}
        # 驱逐/扩容用锁，避免并发修改 _agents 字典
        self._lock = asyncio.Lock()

    async def get_agent(self, cwd: str) -> BaseAgent:
        """
        获取或创建 cwd 对应的 Agent

        Args:
            cwd: 工作目录

        Returns:
            ClaudeAgent 实例
        """
        # 复用已有 Agent
        if cwd in self._agents:
            self._last_active[cwd] = time.time()
            return self._agents[cwd]

        # 需要创建新 Agent，先清理旧实例
        async with self._lock:
            if len(self._agents) >= self.max_active:
                await self._evict_oldest_locked()

            # 双重检查：可能并发期间另一协程已创建
            if cwd in self._agents:
                self._last_active[cwd] = time.time()
                return self._agents[cwd]

            # 创建新 Agent
            agent = ClaudeAgent(cwd=cwd)

            self._agents[cwd] = agent
            self._last_active[cwd] = time.time()

        logger.info(f"创建新 Claude Agent，cwd={cwd}")
        return agent

    async def _evict_oldest_locked(self):
        """驱逐最久未使用的 Agent（调用方须持有 _lock）。"""
        if not self._agents:
            return

        # 找到最久未使用的
        oldest_cwd = min(self._last_active, key=self._last_active.get)
        await self._close_agent(oldest_cwd)
        logger.info(f"驱逐旧 Agent，cwd={oldest_cwd}")

    async def _close_agent(self, cwd: str):
        """关闭指定 cwd 的 Agent"""
        if cwd in self._agents:
            try:
                await self._agents[cwd].close()
            except Exception as e:
                logger.warning(f"关闭 Agent 失败，cwd={cwd}: {e}")
            finally:
                del self._agents[cwd]
                self._last_active.pop(cwd, None)

    async def release_agent(self, cwd: str):
        """释放指定 cwd 的 Agent（可选，Manager 会自动管理）"""
        # 不立即关闭，保留复用
        pass

    def resize(self, max_active: int):
        """调整最大并发 Agent 数量。引擎按微服务数自动扩容时调用。"""
        self.max_active = max(max_active, self.max_active)
        logger.info(f"ClaudeAgentManager 扩容至 max_active={self.max_active}")

    async def shutdown_all(self):
        """关闭所有 Agent"""
        async with self._lock:
            cws = list(self._agents.keys())
        for cwd in cws:
            await self._close_agent(cwd)

        logger.info(f"已关闭所有 {len(cws)} 个 Agent")

    async def execute(
        self,
        cwd: str,
        prompt: str,
        allowed_tools: str = "read,grep,lsp,codesearch",
        output_schema: dict | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """
        便捷方法：获取 Agent 并执行

        Args:
            cwd: 工作目录
            prompt: 执行提示
            allowed_tools: 允许的工具
            output_schema: 输出结构
            timeout: 单次调用超时（秒）

        Returns:
            执行结果
        """
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
        """当前活跃 Agent 数量"""
        return len(self._agents)

    def get_stats(self) -> dict[str, Any]:
        """获取统计信息"""
        return {
            "active_count": len(self._agents),
            "max_active": self.max_active,
            "working_dirs": list(self._agents.keys()),
        }