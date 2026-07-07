"""Agent 后端工厂。

按后端开关实例化对应的 AgentManager，让 engine.py 不感知具体后端实现。

用法：
    from src.agent_factory import create_agent_manager

    manager = create_agent_manager(
        backend="opencode",      # 或 "claude"
        max_active=5,
        opencode_config=OpenCodeConfig(model="volcengine/glm-5.2"),
    )
    agent = await manager.get_agent(cwd)
    result = await agent.execute(prompt, allowed_tools, output_schema)
"""
import logging
from typing import Any

from src.agents.base import BaseAgentManager

logger = logging.getLogger(__name__)


class OpenCodeConfig:
    """OpenCode 后端的配置参数。

    封装成 dataclass-like 结构，避免 agent_factory 函数签名爆炸。
    """

    def __init__(
        self,
        model: str = "volcengine/glm-5.2",
        hostname: str = "127.0.0.1",
        port_start: int = 4096,
        default_timeout: float = 300.0,
        health_check_timeout: float = 30.0,
        idle_timeout: float = 60.0,
        cors_origins: list[str] | None = None,
    ):
        """
        Args:
            model: 模型标识，格式 providerID/modelID（默认 volcengine/glm-5.2）
            hostname: opencode server 监听地址
            port_start: opencode server 端口分配起始值
            default_timeout: Agent 单次请求默认超时（秒）
            health_check_timeout: server 启动健康检查总超时（秒）
            idle_timeout: server 空闲回收阈值（秒）
            cors_origins: CORS 允许的来源列表
        """
        self.model = model
        self.hostname = hostname
        self.port_start = port_start
        self.default_timeout = default_timeout
        self.health_check_timeout = health_check_timeout
        self.idle_timeout = idle_timeout
        self.cors_origins = cors_origins or []


def create_agent_manager(
    backend: str,
    max_active: int = 5,
    opencode_config: OpenCodeConfig | None = None,
) -> BaseAgentManager:
    """按后端标识创建对应的 AgentManager。

    Args:
        backend: "claude" 或 "opencode"
        max_active: 最大并发 Agent 数量
        opencode_config: OpenCode 后端专属配置（backend="opencode" 时生效）

    Returns:
        BaseAgentManager 实例

    Raises:
        ValueError: 未知的 backend 标识
        ImportError: 对应后端的依赖未安装
    """
    backend_lower = backend.lower().strip()

    if backend_lower == "claude":
        try:
            from src.claude_manager import ClaudeAgentManager
        except ImportError as e:
            raise ImportError(
                "Claude 后端依赖 claude-agent-sdk 未安装，请执行: pip install claude-agent-sdk"
            ) from e
        logger.info(f"创建 ClaudeAgentManager (max_active={max_active})")
        return ClaudeAgentManager(max_active=max_active)

    if backend_lower == "opencode":
        try:
            from src.opencode_manager import OpenCodeAgentManager
        except ImportError as e:
            raise ImportError(
                "OpenCode 后端依赖缺失，请确认已安装 aiohttp: pip install aiohttp"
            ) from e
        cfg = opencode_config or OpenCodeConfig()
        logger.info(
            f"创建 OpenCodeAgentManager (max_active={max_active}, "
            f"model={cfg.model}, port_start={cfg.port_start})"
        )
        return OpenCodeAgentManager(
            max_active=max_active,
            config=cfg,
        )

    raise ValueError(
        f"未知的 agent backend: {backend!r}，支持 'claude' 或 'opencode'"
    )


def list_available_backends() -> list[str]:
    """探测当前环境可用的后端列表（用于 CLI 帮助信息）。"""
    available: list[str] = []

    try:
        import claude_agent_sdk  # noqa: F401

        available.append("claude")
    except ImportError:
        pass

    try:
        import aiohttp  # noqa: F401

        available.append("opencode")
    except ImportError:
        pass

    return available


def validate_backend(backend: str) -> tuple[bool, str]:
    """校验后端是否可用，返回 (可用, 原因)。

    用于 CLI 启动时提前失败，避免跑到一半才发现依赖缺失。
    """
    backend_lower = backend.lower().strip()

    if backend_lower == "claude":
        try:
            import claude_agent_sdk  # noqa: F401

            return True, "OK"
        except ImportError:
            return False, "claude-agent-sdk 未安装，执行: pip install claude-agent-sdk"

    if backend_lower == "opencode":
        try:
            import aiohttp  # noqa: F401
            from src.agents.platform_utils import resolve_opencode_executable

            exe = resolve_opencode_executable()
            if exe is None:
                return False, (
                    "opencode 可执行文件未找到，请安装 opencode-ai 或设置 OPENCODE_BIN 环境变量。"
                    "安装: npm install -g opencode-ai"
                )
            return True, f"OK (opencode: {exe})"
        except ImportError:
            return False, "aiohttp 未安装，执行: pip install aiohttp"

    return False, f"未知后端: {backend!r}，支持 'claude' 或 'opencode'"


# 类型导出，方便 engine.py import
__all__ = [
    "OpenCodeConfig",
    "create_agent_manager",
    "list_available_backends",
    "validate_backend",
]
