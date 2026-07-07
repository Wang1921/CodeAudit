"""
Claude Agent SDK 实现

使用 claude-agent-sdk 调用本地 Claude Code CLI
"""
import logging
import time
from typing import Any

import jsonschema
from claude_agent_sdk import (
    ClaudeAgentOptions,
    query,
    Message,
    TextBlock,
    ToolUseBlock,
    AssistantMessage,
    SystemMessage,
    UserMessage,
    ResultMessage,
)

from src.agents.base import BaseAgent, try_extract_json
from src.agents.platform_utils import build_codegraph_mcp_config_for_claude_sdk, is_codegraph_available

logger = logging.getLogger(__name__)


class ClaudeAgent(BaseAgent):
    """使用 Claude Agent SDK 的 Agent"""

    def __init__(self, cwd: str):
        self.cwd = cwd
        self._session_tracker = None
        self._current_task_id = None

    def set_session_tracker(self, tracker):
        """设置 session 追踪器回调"""
        self._session_tracker = tracker

    def set_current_task(self, task_id):
        """设置当前任务 ID"""
        self._current_task_id = task_id

    def _build_options(self, allowed_tools: str, output_schema: dict | None) -> ClaudeAgentOptions:
        """构建 ClaudeAgentOptions"""
        # 基础工具列表
        base_tools = ["read", "bash", "glob", "grep", "skill", "write"]

        options_kwargs: dict[str, Any] = {
            "tools": ['Read', 'Bash', 'Glob', 'Grep', 'Skill', 'Write'],
            "skills": ['blue-validator', 'red-validator', 'logic-auditor',
                       'reverse-tracer', 'config-validator'],
            "setting_sources": ["user", "project"],
            "cwd": self.cwd,
            "permission_mode": "bypassPermissions",
            "allowed_tools": list(base_tools),
        }

        # CodeGraph MCP 配置（仅在 codegraph 可用时挂载）
        if is_codegraph_available():
            codegraph_tools = [
                "mcp__codegraph__codegraph_explore",
                "mcp__codegraph__codegraph_search",
                "mcp__codegraph__codegraph_callers",
                "mcp__codegraph__codegraph_callees",
                "mcp__codegraph__codegraph_impact",
                "mcp__codegraph__codegraph_node",
                "mcp__codegraph__codegraph_files",
                "mcp__codegraph__codegraph_status",
            ]
            options_kwargs["allowed_tools"] = list(base_tools) + codegraph_tools
            options_kwargs["mcp_servers"] = {
                "codegraph": build_codegraph_mcp_config_for_claude_sdk(),
            }
        else:
            logger.info("codegraph 未安装，Claude 后端跳过 MCP 挂载")

        options = ClaudeAgentOptions(**options_kwargs)

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
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """
        执行 prompt，返回结果

        返回格式: {"response": str, "usage": dict, "_tokens": int, "structured_output": dict|None}

        Args:
            prompt: 提示词
            allowed_tools: 允许的工具（Claude 后端会忽略此参数，使用内置工具集）
            output_schema: 输出 JSON Schema
            timeout: 单次调用超时（秒）。Claude 后端当前不支持 per-call 超时，
                     由 SDK 默认行为控制；参数保留以兼容接口。
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
            # 更新状态为运行中
            self._session_tracker.update_claude_session_status(self._current_task_id, "running")

        # 收集所有消息
        messages: list[Message] = []
        turn_count = 0
        turn_history: list[dict] = []

        try:
            async for msg in query(prompt=prompt, options=options):
                messages.append(msg)
                turn_count += 1

                # 构建轮次条目
                turn_entry: dict[str, Any] = {
                    "turn": turn_count,
                    "timestamp": time.time(),
                    "type": None,
                }

                if isinstance(msg, SystemMessage):
                    turn_entry["type"] = "system"
                    turn_entry["subtype"] = msg.subtype
                elif isinstance(msg, AssistantMessage):
                    turn_entry["type"] = "assistant"
                    # 提取文本
                    texts = [b.text for b in msg.content if isinstance(b, TextBlock)]
                    turn_entry["text"] = texts[0] if texts else ""
                    # 提取工具调用
                    tool_calls = [b.name for b in msg.content if isinstance(b, ToolUseBlock)]
                    turn_entry["tool_calls"] = tool_calls
                elif isinstance(msg, UserMessage):
                    turn_entry["type"] = "user"
                    # 提取工具结果
                    texts = [b.text for b in msg.content if isinstance(b, TextBlock)]
                    turn_entry["result"] = texts[0] if texts else ""
                elif isinstance(msg, ResultMessage):
                    turn_entry["type"] = "result"
                    turn_entry["subtype"] = msg.subtype
                    turn_entry["result"] = msg.result or ""
                    turn_entry["usage"] = msg.usage

                turn_history.append(turn_entry)

                # 实时写入 session_tracker，让前端能实时看到
                if self._session_tracker and self._current_task_id:
                    self._session_tracker.update_turn_history(
                        self._current_task_id,
                        turn_history.copy()  # 复制避免引用问题
                    )

                if isinstance(msg, ResultMessage):
                    # 结果消息，包含 usage 信息
                    break
                elif isinstance(msg, AssistantMessage):
                    # 更新状态为 running
                    if self._session_tracker and self._current_task_id:
                        self._session_tracker.update_claude_session_status(self._current_task_id, "running")

        except Exception as e:
            logger.error(f"Claude Agent 执行失败: {e}")
            # 更新状态为失败
            if self._session_tracker and self._current_task_id:
                self._session_tracker.update_claude_session_status(self._current_task_id, "error")
            raise
        finally:
            # 更新会话消息和 token 消耗
            if self._session_tracker and self._current_task_id:
                formatted_messages = self._format_messages_for_frontend(messages)
                tokens_info = self._extract_tokens_info(messages)
                self._session_tracker.update_claude_session(
                    self._current_task_id,
                    formatted_messages,
                    tokens_info
                )
                # 取消 session 追踪
                self._session_tracker.untrack_session(self._current_task_id)
                # 清理 task_id，避免下一个任务复用时使用旧值
                self._current_task_id = None

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
        """尝试从文本中提取符合 schema 的 JSON（委托给 agents.base 公共工具）。"""
        return try_extract_json(text, schema)

    def _format_messages_for_frontend(self, messages: list[Message]) -> list:
        """将消息格式化为前端可读的格式"""
        formatted = []
        for msg in messages:
            msg_entry = {"info": {"role": "unknown", "time": {"created": time.time()}}, "parts": []}

            if isinstance(msg, SystemMessage):
                msg_entry["info"]["role"] = "system"
                msg_entry["parts"].append({"type": "text", "text": f"[System: {msg.subtype}]"})
            elif isinstance(msg, AssistantMessage):
                msg_entry["info"]["role"] = "assistant"
                for block in msg.content:
                    if isinstance(block, TextBlock):
                        msg_entry["parts"].append({"type": "text", "text": block.text})
                    elif isinstance(block, ToolUseBlock):
                        tool_entry = {
                            "type": "tool",
                            "name": block.name,
                            "tool": block.name,
                            "input": block.input,
                            "state": {"status": "completed" if block.id else "pending"}
                        }
                        msg_entry["parts"].append(tool_entry)
            elif isinstance(msg, ResultMessage):
                msg_entry["info"]["role"] = "result"
                msg_entry["parts"].append({"type": "text", "text": msg.result or "[completed]"})

            formatted.append(msg_entry)
        return formatted

    def _extract_tokens_info(self, messages: list[Message]) -> dict:
        """从消息中提取 token 消耗信息"""
        tokens = {"total": 0, "input": 0, "output": 0, "reasoning": 0}
        for msg in messages:
            if isinstance(msg, ResultMessage) and msg.usage:
                tokens["input"] = msg.usage.get("input_tokens", 0)
                tokens["output"] = msg.usage.get("output_tokens", 0)
                tokens["reasoning"] = msg.usage.get("reasoning_tokens", 0)
                tokens["total"] = tokens["input"] + tokens["output"] + tokens["reasoning"]
                break
        return tokens

    async def close(self):
        """关闭 agent（当前实现无需清理资源）"""
        pass