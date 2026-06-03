"""
Claude Agent SDK 实现

使用 claude-agent-sdk 调用本地 Claude Code CLI
"""
import json
import logging
from typing import Any, AsyncIterator

import jsonschema
from claude_agent_sdk import (
    ClaudeAgentOptions,
    query,
    Message,
    TextBlock,
    ToolUseBlock,
    AssistantMessage,
    SystemMessage,
    ResultMessage,
)

logger = logging.getLogger(__name__)


class ClaudeAgent:
    """使用 Claude Agent SDK 的 Agent"""

    def __init__(
        self,
        cwd: str,
        timeout: int = 1800,
        system_prompt: str | None = None,
    ):
        self.cwd = cwd
        self.timeout = timeout
        self.system_prompt = system_prompt
        self._session_tracker = None
        self._current_task_id = None

        # 估算 max_turns: 每轮约 30-60 秒
        self.max_turns = max(10, timeout // 60)

    def set_session_tracker(self, tracker):
        """设置 session 追踪器回调"""
        self._session_tracker = tracker

    def set_current_task(self, task_id):
        """设置当前任务 ID"""
        self._current_task_id = task_id

    def _build_options(self, allowed_tools: str, output_schema: dict | None) -> ClaudeAgentOptions:
        """构建 ClaudeAgentOptions"""
        options = ClaudeAgentOptions(
            tools=['Read', 'Bash', 'Glob', 'Grep', 'Skill'],
            skills=['blue-validator', 'red-validator', 'logic-auditor', 'reverse-tracer'],
            setting_sources=["user", "project"],
            cwd=self.cwd,
            max_turns=self.max_turns,
            permission_mode="acceptEdits",
        )

        if self.system_prompt:
            options.system_prompt = self.system_prompt

        if output_schema:
            options.output_format = {
                "type": "json_schema",
                "schema": output_schema,
            }

        return options

    async def execute(
        self,
        prompt: str,
        allowed_tools: str = "read,grep,lsp,codesearch",
        output_schema: dict | None = None,
    ) -> dict[str, Any]:
        """
        执行 prompt，返回结果

        返回格式: {"response": str, "usage": dict, "_tokens": int, "structured_output": dict|None}
        """
        options = self._build_options(allowed_tools, output_schema)

        # 注册 session 追踪
        if self._session_tracker and self._current_task_id:
            # Claude Agent SDK 不像 OpenCode 有 session_id，使用 cwd 作为标识
            self._session_tracker.track_session(
                self._current_task_id,
                f"claude-{self.cwd}",
                port=0,  # 无端口概念
                hostname="cli"
            )

        # 收集所有消息
        messages: list[Message] = []

        try:
            async for msg in query(prompt=prompt, options=options):
                messages.append(msg)

                if isinstance(msg, ResultMessage):
                    # 结果消息，包含 usage 信息
                    break

        except Exception as e:
            logger.error(f"Claude Agent 执行失败: {e}")
            raise
        finally:
            # 取消 session 追踪
            if self._session_tracker and self._current_task_id:
                self._session_tracker.untrack_session(self._current_task_id)

        # 提取结果
        return self._extract_result(messages, output_schema)

    def _extract_result(
        self,
        messages: list[Message],
        output_schema: dict | None = None
    ) -> dict[str, Any]:
        """从消息流中提取结果"""
        response_text = ""
        tokens = {}
        total_tokens = 0
        structured_output = None

        for msg in messages:
            if isinstance(msg, AssistantMessage):
                for block in msg.content:
                    if isinstance(block, TextBlock):
                        response_text += block.text

            elif isinstance(msg, ResultMessage):
                # 提取使用统计
                tokens = {
                    "input_tokens": msg.usage.get("input_tokens", 0) if msg.usage else 0,
                    "output_tokens": msg.usage.get("output_tokens", 0) if msg.usage else 0,
                }
                total_tokens = msg.total_cost_usd  # 这是成本，不是 token 数
                # Claude SDK 返回的是成本，需要估算 token
                # 简化处理：用成本反推（约 $15/1M output）
                if total_tokens > 0:
                    total_tokens = int(total_tokens * 1000000 / 15)

                # 如果配置了 output_format，直接使用 structured_output
                if output_schema and msg.structured_output is not None:
                    try:
                        jsonschema.validate(msg.structured_output, output_schema)
                        structured_output = msg.structured_output
                    except jsonschema.ValidationError as e:
                        logger.warning(f"服务端返回的 structured_output 验证失败: {e}")

            elif isinstance(msg, SystemMessage):
                pass

        # 如果没有从 structured_output 获取，尝试从响应文本提取
        if not structured_output and output_schema and response_text:
            structured_output = self._try_extract_json(response_text, output_schema)

        return {
            "response": response_text,
            "usage": tokens,
            "_tokens": total_tokens,
            "structured_output": structured_output,
        }

    def _try_extract_json(self, text: str, schema: dict) -> dict | None:
        """尝试从文本中提取 JSON"""
        # 查找 JSON 块
        start = text.find("```json")
        if start == -1:
            start = text.find("```")
        if start != -1:
            start = text.find("}", start) + 1
            end = text.find("```", start)
            if end != -1:
                json_str = text[start:end].strip()
                try:
                    data = json.loads(json_str)
                    # 验证 schema
                    jsonschema.validate(data, schema)
                    return data
                except (json.JSONDecodeError, jsonschema.ValidationError):
                    pass

        # 直接尝试解析
        try:
            data = json.loads(text)
            jsonschema.validate(data, schema)
            return data
        except (json.JSONDecodeError, jsonschema.ValidationError):
            pass

        return None

    async def close(self):
        """关闭 agent（当前实现无需清理资源）"""
        pass


class ClaudeAgentAsync(ClaudeAgent):
    """支持流式交互的 Claude Agent"""

    async def execute_stream(
        self,
        prompt: str,
        allowed_tools: str = "read,grep,lsp,codesearch",
    ) -> AsyncIterator[Message]:
        """流式执行，返回消息迭代器"""
        options = self._build_options(allowed_tools, None)

        async for msg in query(prompt=prompt, options=options):
            yield msg
            if isinstance(msg, ResultMessage):
                break