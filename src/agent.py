import json
import logging
import asyncio
import aiohttp
from typing import Dict, Any
from . import prompts

class OpenCodeAgent:
    def __init__(self, port: int, timeout: int = 1800):
        self.port = port
        self.timeout = timeout
        # 需根据 opencode 实际运行的 API 端点调整 (如 /api/run 或 /v1/chat/completions)
        self.api_url = f"http://127.0.0.1:{self.port}/api/run"

    async def execute(self, prompt: str, allowed_tools: str = "read,grep,lsp,codesearch") -> Dict[str, Any]:
        payload = {
            "prompt": prompt,
            "tools": allowed_tools.split(","),
            "format": "json"
        }

        async with aiohttp.ClientSession() as session:
            try:
                client_timeout = aiohttp.ClientTimeout(total=self.timeout)
                async with session.post(self.api_url, json=payload, timeout=client_timeout) as response:
                    if response.status != 200:
                        err = await response.text()
                        raise RuntimeError(f"OpenCode Server 异常: {err}")

                    result_text = await response.text()
                    try:
                        # 假设返回体包含 JSON 输出和 Tokens
                        data = json.loads(result_text)
                        data['_tokens'] = data.get('usage', {}).get('total_tokens', 0)
                        return data
                    except json.JSONDecodeError as e:
                        # 这里保留原来的容错重试逻辑，防止大模型乱格式
                        return await self._retry(session, result_text, str(e), allowed_tools)
            except asyncio.TimeoutError:
                raise TimeoutError("Agent HTTP 执行超时")

    async def _retry(self, session, raw_output, error_msg, allowed_tools):
        logging.warning("JSON 验证失败，尝试触发修复重试...")
        truncated = raw_output if len(raw_output) <= 2000 else raw_output[:2000] + "\n...[已截断]..."
        retry_prompt = prompts.format_retry_prompt(error_details=error_msg, raw_output=truncated)

        payload = {"prompt": retry_prompt, "tools": allowed_tools.split(","), "format": "json"}
        async with session.post(self.api_url, json=payload, timeout=aiohttp.ClientTimeout(total=300)) as resp:
            text = await resp.text()
            try:
                return json.loads(text)
            except Exception:
                raise ValueError(f"重试依然失败: {text[:500]}")
