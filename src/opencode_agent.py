"""
OpenCode HTTP Agent 客户端。

通过 OpenCode server 的 HTTP API 发送 prompt，获取 LLM 结构化输出。
每个 execute() 调用：创建 session → 发消息 → 解析响应 → 删除 session。

参考 doc/structured-output-guide.md 的 API 契约。
"""
import asyncio
import json
import logging
import time
import uuid
from typing import Any

import aiohttp
import jsonschema

from src.agents.base import BaseAgent, try_extract_json

logger = logging.getLogger(__name__)


class OpenCodeAgent(BaseAgent):
    """OpenCode HTTP server 后端的 Agent 实现。"""

    def __init__(
        self,
        cwd: str,
        port: int,
        hostname: str = "127.0.0.1",
        model: str = "volcengine/glm-5.2",
        default_timeout: float = 300.0,
    ):
        """
        Args:
            cwd: 工作目录（用于标识，实际 cwd 由 opencode serve 启动时确定）
            port: OpenCode server 监听端口
            hostname: server 监听地址
            model: 模型标识，格式 providerID/modelID
            default_timeout: 单次请求默认超时（秒）
        """
        self.cwd = cwd
        self.port = port
        self.hostname = hostname
        self.base_url = f"http://{hostname}:{port}"
        self.model = model
        self.default_timeout = default_timeout
        self._session_tracker = None
        self._current_task_id = None

    def set_session_tracker(self, tracker):
        self._session_tracker = tracker

    def set_current_task(self, task_id):
        self._current_task_id = task_id

    async def execute(
        self,
        prompt: str,
        allowed_tools: str = "lsp,read,codesearch",
        output_schema: dict | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """执行 prompt，返回统一结果字典。

        Args:
            prompt: 提示词
            allowed_tools: 逗号分隔的工具名（OpenCode 内置 lsp/read/codesearch/grep/glob 等）
            output_schema: 输出 JSON Schema，非空时启用结构化输出
            timeout: 单次调用超时（秒），None 用 default_timeout
        """
        effective_timeout = timeout or self.default_timeout
        session_id = None
        try:
            # 1. 创建 session
            session_id = await self._create_session()

            # 2. 注册 session 追踪（state_tracker poller 会自动拉取 /session/status）
            if self._session_tracker and self._current_task_id:
                self._session_tracker.track_session(
                    self._current_task_id,
                    session_id,
                    port=self.port,
                    hostname=self.hostname,
                )
                self._session_tracker.update_claude_session_status(self._current_task_id, "running")

            # 3. 发送消息（同步接口，带结构化输出 format）
            response_data = await self._send_message(session_id, prompt, allowed_tools, output_schema,
                                                     effective_timeout)

            # 4. 解析响应为统一结果字典
            result = self._parse_response(response_data, output_schema)

            # 5. 更新 session 追踪的 token / messages
            if self._session_tracker and self._current_task_id:
                self._session_tracker.update_claude_session(
                    self._current_task_id,
                    self._format_messages_for_frontend(response_data),
                    result.get("usage", {"total": 0, "input": 0, "output": 0, "reasoning": 0}),
                )

            return result
        finally:
            # 6. 取消追踪 + 删除 session（异常容错，不阻塞主流程）
            if self._session_tracker and self._current_task_id:
                try:
                    self._session_tracker.untrack_session(self._current_task_id)
                except Exception:
                    pass
                self._current_task_id = None
            if session_id:
                await self._delete_session(session_id)

    async def _create_session(self) -> str:
        """POST /session 创建新会话，返回 session id。"""
        async with aiohttp.ClientSession() as http:
            async with http.post(
                f"{self.base_url}/session",
                json={},
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    raise RuntimeError(f"创建 session 失败 status={resp.status}: {body}")
                data = await resp.json()
                session_id = data.get("id")
                if not session_id:
                    raise RuntimeError(f"session 响应缺少 id 字段: {data}")
                return session_id

    async def _send_message(
        self,
        session_id: str,
        prompt: str,
        allowed_tools: str,
        output_schema: dict | None,
        timeout: float,
    ) -> dict:
        """POST /session/{id}/message 发送消息，返回完整响应 JSON。"""
        # 拆分工具列表
        tools = [t.strip() for t in allowed_tools.split(",") if t.strip()] if allowed_tools else []

        payload: dict[str, Any] = {
            "messageID": f"msg{uuid.uuid4().hex[:24]}",
            "model": self._model_payload(),
            "parts": [{"type": "text", "text": prompt}],
        }
        if tools:
            payload["tools"] = tools
        if output_schema:
            payload["format"] = {
                "type": "json_schema",
                "schema": output_schema,
            }

        async with aiohttp.ClientSession() as http:
            async with http.post(
                f"{self.base_url}/session/{session_id}/message",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    raise RuntimeError(
                        f"发送消息失败 status={resp.status} session={session_id}: {body[:500]}"
                    )
                return await resp.json()

    def _model_payload(self) -> dict[str, str]:
        """解析 self.model (providerID/modelID) 为 API 要求的对象结构。"""
        if "/" in self.model:
            provider_id, model_id = self.model.split("/", 1)
            return {"providerID": provider_id, "modelID": model_id}
        # 兜底：整体作为 modelID
        return {"providerID": "volcengine", "modelID": self.model}

    def _parse_response(self, response_data: dict, output_schema: dict | None) -> dict[str, Any]:
        """把 OpenCode 响应解析为统一结果字典。

        响应结构（见 structured-output-guide.md）：
        {
          "info": {"id":..., "role":"assistant", "structured": {...}, "error": null, "tokens": {...}},
          "parts": [{"type":"text","text":...}, {"type":"tool",...}, {"type":"reasoning",...}]
        }
        """
        info = response_data.get("info", {}) or {}
        parts = response_data.get("parts", []) or []

        # 1. 提取文本输出
        response_text = ""
        for part in parts:
            if isinstance(part, dict) and part.get("type") == "text":
                response_text += part.get("text", "")

        # 2. 提取结构化输出
        structured_output = None
        raw_structured = info.get("structured")
        if output_schema and isinstance(raw_structured, dict):
            try:
                jsonschema.validate(raw_structured, output_schema)
                structured_output = raw_structured
            except jsonschema.ValidationError as e:
                logger.warning(f"OpenCode 服务端 structured 校验失败: {e}")

        # 3. 服务端未通过 → coerce 救回
        if not structured_output and output_schema and response_text:
            structured_output = try_extract_json(response_text, output_schema)

        # 4. 提取 token 用量
        tokens_info = info.get("tokens", {}) or {}
        usage = {
            "input_tokens": int(tokens_info.get("input", 0)),
            "output_tokens": int(tokens_info.get("output", 0)),
        }
        reasoning_tokens = int(tokens_info.get("reasoning", 0))
        total_tokens = usage["input_tokens"] + usage["output_tokens"] + reasoning_tokens

        return {
            "response": response_text,
            "usage": usage,
            "_tokens": total_tokens,
            "structured_output": structured_output,
        }

    def _format_messages_for_frontend(self, response_data: dict) -> list:
        """把 OpenCode 响应转为前端可读的消息列表格式（与 ClaudeAgent 对齐）。"""
        formatted = []
        info = response_data.get("info", {}) or {}
        parts = response_data.get("parts", []) or []

        # assistant 消息
        msg_entry = {
            "info": {"role": "assistant", "time": {"created": time.time()}},
            "parts": [],
        }
        for part in parts:
            if not isinstance(part, dict):
                continue
            ptype = part.get("type")
            if ptype == "text":
                msg_entry["parts"].append({"type": "text", "text": part.get("text", "")})
            elif ptype == "reasoning":
                msg_entry["parts"].append({"type": "text", "text": f"[reasoning] {part.get('text', '')}"})
            elif ptype == "tool":
                tool_name = part.get("tool", "unknown")
                state = part.get("state", {}) or {}
                msg_entry["parts"].append({
                    "type": "tool",
                    "name": tool_name,
                    "tool": tool_name,
                    "input": state.get("input", {}),
                    "state": {"status": state.get("status", "completed")},
                })
        formatted.append(msg_entry)

        # 若有错误信息，附加一条 result 消息
        if info.get("error"):
            err = info["error"]
            err_name = err.get("name", "Error") if isinstance(err, dict) else str(err)
            formatted.append({
                "info": {"role": "result", "time": {"created": time.time()}},
                "parts": [{"type": "text", "text": f"[error] {err_name}"}],
            })
        return formatted

    async def _delete_session(self, session_id: str):
        """DELETE /session/{id} 删除会话（容错）。"""
        try:
            async with aiohttp.ClientSession() as http:
                async with http.delete(
                    f"{self.base_url}/session/{session_id}",
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status not in (200, 204, 404):
                        logger.debug(f"删除 session {session_id} 返回 status={resp.status}")
        except Exception as e:
            logger.debug(f"删除 session {session_id} 异常（不影响主流程）: {e}")

    async def close(self):
        """OpenCodeAgent 无需清理资源（每次 execute 用独立 session）。"""
        pass
