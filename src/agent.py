import json
import logging
import asyncio
import aiohttp
from typing import Dict, Any, Optional, List
from . import prompts

logger = logging.getLogger(__name__)

class OpenCodeAgent:
    def __init__(
        self,
        port: int,
        hostname: str = "127.0.0.1",
        timeout: int = 1800,
        auto_create_session: bool = True
    ):
        self.port = port
        self.hostname = hostname
        self.timeout = timeout
        self.auto_create_session = auto_create_session
 
        self._base_url = f"http://{self.hostname}:{self.port}"
        self._session_id: Optional[str] = None
        self._http_session: Optional[aiohttp.ClientSession] = None
        self._session_tracker = None
        self._current_task_id = None

    async def _get_http_session(self) -> aiohttp.ClientSession:
        if not self._http_session or self._http_session.closed:
            self._http_session = aiohttp.ClientSession()
        return self._http_session

    async def _create_session(self) -> str:
        """创建新的 opencode 会话"""
        url = f"{self._base_url}/session"
        session = await self._get_http_session()
 
        async with session.post(url, json={}) as resp:
            if resp.status != 200:
                err = await resp.text()
                raise RuntimeError(f"创建会话失败: {err}")
            data = await resp.json()
            session_id = data["id"]
            
            # 通知 tracker
            if self._session_tracker and self._current_task_id:
                self._session_tracker.track_session(
                    self._current_task_id,
                    session_id,
                    self.port
                )
            
            return session_id

    async def _ensure_session(self) -> str:
        """确保会话存在"""
        if self._session_id is None:
            self._session_id = await self._create_session()
            logger.info(f"创建 opencode 会话: {self._session_id}")
        return self._session_id

    async def execute(
        self,
        prompt: str,
        allowed_tools: str = "read,grep,lsp,codesearch",
        output_schema: Optional[Dict[str, Any]] = None,
        format_retry_count: int = 2,
    ) -> Dict[str, Any]:
        """
        发送消息并等待响应。

        当 output_schema 提供时，向 OpenCode 服务端声明 JSON Schema 结构化输出
        （POST body 的 format 字段），服务端会自行校验模型输出并按 retryCount 重试。
        服务端校验通过的 JSON 会以 structured_output 字段返回，优先使用。

        返回格式: {"response": str, "usage": dict, "_tokens": int, "structured_output": dict|None}
        """
        session_id = await self._ensure_session()
        url = f"{self._base_url}/session/{session_id}/message"
        session = await self._get_http_session()

        payload: Dict[str, Any] = {
            "parts": [{"type": "text", "text": prompt}]
        }
        if output_schema is not None:
            payload["format"] = {
                "type": "json_schema",
                "schema": output_schema,
                "retryCount": format_retry_count,
            }

        try:
            client_timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with session.post(url, json=payload, timeout=client_timeout) as response:
                if response.status != 200:
                    err = await response.text()
                    raise RuntimeError(f"OpenCode Server 异常: {err}")

                result_text = await response.text()
                try:
                    # opencode 返回格式: {info: Message, parts: Part[]}
                    data = json.loads(result_text)
                    info = data.get("info", {}) or {}
                    parts = data.get("parts", []) or []

                    # 结构化输出实现方式：opencode 内部生成一次 StructuredOutput tool call，
                    # 校验通过的 JSON 放在 part.state.input（type=="tool" && tool=="StructuredOutput"）
                    structured_output = None
                    for part in parts:
                        if part.get("type") == "tool" and part.get("tool") == "StructuredOutput":
                            state = part.get("state", {}) or {}
                            if state.get("status") == "completed":
                                structured_output = state.get("input")
                                break

                    # 结构化输出优先：当服务端产出 StructuredOutput 时，以它为准
                    # （text part 里往往是 reasoning 前言，不可作为最终 JSON）
                    if structured_output is not None:
                        content = json.dumps(structured_output, ensure_ascii=False)
                    else:
                        content = ""
                        for part in parts:
                            if part.get("type") == "text":
                                content = part.get("text", "")
                                if content:
                                    break

                    # opencode 1.4.x 的 token 统计在 info.tokens（非 info.usage）
                    tokens = info.get("tokens") or {}
                    total_tokens = tokens.get("total", 0) if isinstance(tokens, dict) else 0

                    return {
                        "response": content,
                        "usage": tokens,
                        "_tokens": total_tokens,
                        "structured_output": structured_output,
                    }
                except json.JSONDecodeError as e:
                    return await self._retry(session, result_text, str(e), allowed_tools)
        except asyncio.TimeoutError:
            raise TimeoutError("Agent HTTP 执行超时")

    async def _retry(
        self,
        session: aiohttp.ClientSession,
        raw_output: str,
        error_msg: str,
        allowed_tools: str
    ) -> Dict[str, Any]:
        """重试修复格式错误的响应"""
        logger.warning("JSON 验证失败，尝试触发修复重试...")
        truncated = raw_output if len(raw_output) <= 2000 else raw_output[:2000] + "\n...[已截断]..."
        retry_prompt = prompts.format_retry_prompt(error_details=error_msg, raw_output=truncated)
 
        sid = await self._ensure_session()
        url = f"{self._base_url}/session/{sid}/message"
 
        payload = {"parts": [{"type": "text", "text": retry_prompt}]}
 
        async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=300)) as resp:
            text = await resp.text()
            try:
                data = json.loads(text)
                parts = data.get("parts", [])
                content = ""
                for part in parts:
                    if part.get("type") == "text":
                        content = part.get("text", "")
                        break
                return {
                    "response": content,
                    "usage": data.get("info", {}).get("usage", {}),
                    "_tokens": data.get("info", {}).get("usage", {}).get("total_tokens", 0)
                }
            except Exception as e:
                raise ValueError(f"重试依然失败: {text[:500]}, 错误: {e}")

    async def delete_session(self) -> None:
        """删除当前会话"""
        if self._session_id is None:
            return

        url = f"{self._base_url}/session/{self._session_id}"
        session = await self._get_http_session()

        try:
            async with session.delete(url) as resp:
                if resp.status == 200:
                    logger.info(f"已删除会话: {self._session_id}")
        except Exception as e:
            logger.warning(f"删除会话失败: {e}")
        finally:
            self._session_id = None

    def set_session_tracker(self, tracker):
        """设置 session 追踪器回调"""
        self._session_tracker = tracker
    
    def set_current_task(self, task_id):
        """设置当前任务 ID"""
        self._current_task_id = task_id
    
    async def get_session_status(self, session_id: Optional[str] = None) -> Dict[str, Any]:
        """
        查询 opencode session 状态
        返回: {"type": "busy" | "idle" | "retry", ...}
        """
        sid = session_id or self._session_id
        if not sid:
            return {}
        
        session = await self._get_http_session()
        try:
            async with session.get(f"{self._base_url}/session/status") as resp:
                if resp.status == 200:
                    all_statuses = await resp.json()
                    return all_statuses.get(sid, {})
        except Exception as e:
            logger.warning(f"查询 session 状态失败: {e}")
        return {}
    
    async def get_session_messages(self, session_id: Optional[str] = None, limit: int = 50) -> list:
        """
        查询 opencode session 消息历史
        返回: [{"role": "user|assistant", "parts": [...]}]
        """
        sid = session_id or self._session_id
        if not sid:
            return []
        
        session = await self._get_http_session()
        url = f"{self._base_url}/session/{sid}/message"
        if limit:
            url += f"?limit={limit}"
        
        try:
            async with session.get(url) as resp:
                if resp.status == 200:
                    return await resp.json()
        except Exception as e:
            logger.warning(f"查询 session 消息失败: {e}")
        return []
    
    async def shutdown(self) -> None:
        """关闭资源"""
        if self._session_tracker and self._current_task_id:
            self._session_tracker.untrack_session(self._current_task_id)
        
        if self.auto_create_session:
            await self.delete_session()
        if self._http_session and not self._http_session.closed:
            await self._http_session.close()
 
    async def __aenter__(self):
        return self
 
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.shutdown()
