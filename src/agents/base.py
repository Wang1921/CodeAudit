"""Agent 后端抽象基类与公共工具。

定义 BaseAgent / BaseAgentManager 两个 ABC，以及两个后端共用的：
- 统一结果字典契约
- JSON coerce 救回工具（从 LLM 文本输出里递归找符合 schema 的 dict 候选）

engine.py 通过 BaseAgentManager 接口调用，由 agent_factory 按后端开关实例化。
"""
import json
import logging
import re
from abc import ABC, abstractmethod
from typing import Any

import jsonschema

logger = logging.getLogger(__name__)

# 统一结果字典的键：
#   response: str            —— LLM 文本输出
#   usage: dict              —— {"input_tokens": int, "output_tokens": int}
#   _tokens: int             —— 总 token 数（用于 tracker.add_tokens）
#   structured_output: dict|None —— 已通过 jsonschema 校验的结构化输出
RESULT_KEYS = ("response", "usage", "_tokens", "structured_output")


class BaseAgent(ABC):
    """Agent 后端抽象基类。

    两个后端（ClaudeAgent / OpenCodeAgent）都实现本接口，
    engine.py 通过本接口调用，不感知具体后端。
    """

    def __init__(self, cwd: str):
        self.cwd = cwd
        self._session_tracker = None
        self._current_task_id: str | None = None

    def set_session_tracker(self, tracker):
        """设置 session 追踪器回调（state_tracker.StateTracker 实例）。"""
        self._session_tracker = tracker

    def set_current_task(self, task_id: str | None):
        """设置当前任务 ID（用于关联 session 与 task）。"""
        self._current_task_id = task_id

    @abstractmethod
    async def execute(
        self,
        prompt: str,
        allowed_tools: str = "read,grep,lsp,codesearch",
        output_schema: dict | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """执行 prompt，返回统一结果字典。

        Args:
            prompt: 完整渲染后的 prompt 文本
            allowed_tools: 逗号分隔的工具列表
            output_schema: JSON Schema，启用结构化输出校验
            timeout: 单次执行超时秒数

        Returns:
            {"response": str, "usage": dict, "_tokens": int, "structured_output": dict|None}
        """

    @abstractmethod
    async def close(self):
        """关闭 agent，释放资源。"""


class BaseAgentManager(ABC):
    """Agent 会话管理器抽象基类。

    管理多个 Agent 实例的生命周期与池化复用，engine.py 通过本接口获取 agent。
    """

    def __init__(self, max_active: int = 5):
        self.max_active = max_active

    @abstractmethod
    async def get_agent(self, cwd: str) -> BaseAgent:
        """获取或创建 cwd 对应的 Agent 实例。"""

    @abstractmethod
    async def execute(
        self,
        cwd: str,
        prompt: str,
        allowed_tools: str = "read,grep,lsp,codesearch",
        output_schema: dict | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """便捷方法：获取 Agent 并执行。"""

    @abstractmethod
    async def shutdown_all(self):
        """关闭所有 Agent 与底层资源（如子进程池）。"""

    def resize(self, max_active: int):
        """调整最大并发数。默认实现仅更新属性，子类可覆盖以触发实际扩容。"""
        self.max_active = max(self.max_active, max_active)

    @property
    @abstractmethod
    def active_count(self) -> int:
        """当前活跃 Agent 数量。"""

    @abstractmethod
    def get_stats(self) -> dict[str, Any]:
        """获取统计信息。"""


# ============================================================
# 公共 JSON coerce 工具（两个后端共用）
# ============================================================


def try_extract_json(text: str, schema: dict | None = None) -> dict | None:
    """从 LLM 文本输出里尝试提取符合 schema 的 JSON 对象。

    第 3 层校验的"coerce 救回"逻辑：当服务端结构化输出校验失败时，
    从 LLM 原始 response 文本里递归找候选 dict，选第一个能通过 schema 校验的。

    提取顺序：
    1. ```json ... ``` 代码块
    2. ``` ... ``` 通用代码块
    3. 文本中第一个 { ... } 平衡花括号片段
    4. 整体 json.loads

    Args:
        text: LLM 的原始文本输出
        schema: 可选的 JSON Schema，若提供则对候选做校验

    Returns:
        符合 schema 的 dict，或 None
    """
    if not text:
        return None

    candidates: list[str] = []

    # 1. ```json ... ``` 代码块
    for m in re.finditer(r"```json\s*(.*?)\s*```", text, re.DOTALL):
        candidates.append(m.group(1))

    # 2. ``` ... ``` 通用代码块（非 json 标记的）
    for m in re.finditer(r"```\s*(.*?)\s*```", text, re.DOTALL):
        candidates.append(m.group(1))

    # 3. 文本中所有平衡花括号片段
    candidates.extend(_extract_balanced_braces(text))

    # 4. 整体
    candidates.append(text.strip())

    for candidate in candidates:
        candidate = candidate.strip()
        if not candidate or not candidate.startswith("{"):
            continue
        try:
            data = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        if schema is not None:
            try:
                jsonschema.validate(data, schema)
            except jsonschema.ValidationError:
                continue
        return data

    return None


def _extract_balanced_braces(text: str) -> list[str]:
    """从文本中提取所有顶层平衡的 { ... } 片段。

    处理嵌套花括号，避免截断。用于 coerce 候选收集。
    """
    results: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        if text[i] != "{":
            i += 1
            continue
        depth = 0
        start = i
        in_string = False
        escape = False
        while i < n:
            ch = text[i]
            if in_string:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_string = False
            else:
                if ch == '"':
                    in_string = True
                elif ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        results.append(text[start : i + 1])
                        i += 1
                        break
            i += 1
    return results


def validate_structured_output(
    data: Any,
    schema: dict | None,
    context: str = "",
) -> dict | None:
    """对结构化输出做客户端二次 jsonschema 校验。

    Args:
        data: 待校验的对象（通常来自服务端的 structured_output 字段）
        schema: JSON Schema，None 表示无 schema 约束
        context: 日志上下文描述（如 agent 名）

    Returns:
        校验通过返回 data，否则 None
    """
    if data is None:
        return None
    if schema is None:
        return data if isinstance(data, dict) else None
    if not isinstance(data, dict):
        return None
    try:
        jsonschema.validate(data, schema)
        return data
    except jsonschema.ValidationError as e:
        logger.warning(f"[{context}] structured_output 客户端校验失败: {e.message}")
        return None
