"""
Claude Agent 会话管理器

管理多个 Claude Code CLI 会话，复用 Agent 实例
"""
import asyncio
import logging
import time
from typing import Any

from .claude_agent import ClaudeAgent

logger = logging.getLogger(__name__)


class ClaudeAgentManager:
    """管理多个 Claude Code CLI 会话"""

    def __init__(self, max_active: int = 5, default_timeout: int = 1800):
        """
        初始化管理器

        Args:
            max_active: 最大并发 Agent 数量
            default_timeout: 默认超时时间（秒）
        """
        self.max_active = max_active
        self.default_timeout = default_timeout

        # cwd -> Agent 实例
        self._agents: dict[str, ClaudeAgent] = {}
        # cwd -> 最后活跃时间
        self._last_active: dict[str, float] = {}

    async def get_agent(
        self,
        cwd: str,
        timeout: int | None = None,
        system_prompt: str | None = None,
    ) -> ClaudeAgent:
        """
        获取或创建 cwd 对应的 Agent

        Args:
            cwd: 工作目录
            timeout: 超时时间（秒），None 使用默认值
            system_prompt: 系统提示，None 使用 Agent 默认值

        Returns:
            ClaudeAgent 实例
        """
        # 复用已有 Agent
        if cwd in self._agents:
            self._last_active[cwd] = time.time()
            agent = self._agents[cwd]

            # 如果传入新的 system_prompt，更新
            if system_prompt and agent.system_prompt != system_prompt:
                agent.system_prompt = system_prompt

            return agent

        # 需要创建新 Agent，先清理旧实例
        if len(self._agents) >= self.max_active:
            await self._evict_oldest()

        # 创建新 Agent
        timeout = timeout or self.default_timeout
        agent = ClaudeAgent(
            cwd=cwd,
            timeout=timeout,
            system_prompt=system_prompt,
        )

        self._agents[cwd] = agent
        self._last_active[cwd] = time.time()

        logger.info(f"创建新 Claude Agent，cwd={cwd}，timeout={timeout}s")
        return agent

    async def _evict_oldest(self):
        """驱逐最久未使用的 Agent"""
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

    async def shutdown_all(self):
        """关闭所有 Agent"""
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
        timeout: int | None = None,
        system_prompt: str | None = None,
    ) -> dict[str, Any]:
        """
        便捷方法：获取 Agent 并执行

        Args:
            cwd: 工作目录
            prompt: 执行提示
            allowed_tools: 允许的工具
            output_schema: 输出结构
            timeout: 超时时间
            system_prompt: 系统提示

        Returns:
            执行结果
        """
        agent = await self.get_agent(
            cwd=cwd,
            timeout=timeout,
            system_prompt=system_prompt,
        )

        # 临时覆盖 system_prompt
        original_prompt = agent.system_prompt
        if system_prompt:
            agent.system_prompt = system_prompt

        try:
            result = await agent.execute(
                prompt=prompt,
                allowed_tools=allowed_tools,
                output_schema=output_schema,
            )
        finally:
            # 恢复原始 system_prompt
            agent.system_prompt = original_prompt
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