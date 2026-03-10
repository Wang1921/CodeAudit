import json
import logging
import asyncio
import aiohttp
from typing import Dict, Any, Optional
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
            return data["id"]

    async def _ensure_session(self) -> str:
        """确保会话存在"""
        if self._session_id is None:
            self._session_id = await self._create_session()
            logger.info(f"创建 opencode 会话: {self._session_id}")
        return self._session_id

    async def execute(
        self,
        prompt: str,
        allowed_tools: str = "read,grep,lsp,codesearch"
    ) -> Dict[str, Any]:
        """
        发送消息并等待响应
        返回格式: {"response": str, "usage": dict}
        """
        session_id = await self._ensure_session()
        url = f"{self._base_url}/session/{session_id}/message"
        session = await self._get_http_session()

        # 构建请求体
        payload = {
            "parts": [{"role": "user", "content": prompt}]
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
                    # 提取回复内容
                    parts = data.get("parts", [])
                    content = ""
                    for part in parts:
                        if part.get("role") == "assistant":
                            content = part.get("content", "")
                            break

                    # 构造兼容返回格式
                    return {
                        "response": content,
                        "usage": data.get("info", {}).get("usage", {}),
                        "_tokens": data.get("info", {}).get("usage", {}).get("total_tokens", 0)
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

        session_id = await self._ensure_session()
        url = f"{self._base_url}/session/{session_id}/message"

        payload = {"parts": [{"role": "user", "content": retry_prompt}]}

        async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=300)) as resp:
            text = await resp.text()
            try:
                data = json.loads(text)
                parts = data.get("parts", [])
                content = ""
                for part in parts:
                    if part.get("role") == "assistant":
                        content = part.get("content", "")
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

    async def shutdown(self) -> None:
        """关闭资源"""
        if self.auto_create_session:
            await self.delete_session()
        if self._http_session and not self._http_session.closed:
            await self._http_session.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.shutdown()
