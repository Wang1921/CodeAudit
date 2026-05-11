import asyncio
import json
import logging
from typing import Any

import aiohttp
import jsonschema

from . import prompts

logger = logging.getLogger(__name__)

# 客户端二次校验:即便 opencode 服务端通过了 schema(实测 oneOf 不严),
# 我们仍用 jsonschema.validate 复核 structured_output;失败则同 session 喂提示重试。
MAX_SCHEMA_RETRIES = 3

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
        self._session_id: str | None = None
        self._http_session: aiohttp.ClientSession | None = None
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
        output_schema: dict[str, Any] | None = None,
        format_retry_count: int = 4,
    ) -> dict[str, Any]:
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

        payload: dict[str, Any] = {
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
            data, raw_text, parse_err = await self._post_and_parse(session, url, payload, client_timeout)
            if data is None:
                return await self._retry(session, raw_text, parse_err, allowed_tools)

            so, content, tokens, total_tokens = self._extract_outputs(data)

            if output_schema is not None and so is not None:
                for attempt in range(MAX_SCHEMA_RETRIES):
                    try:
                        jsonschema.validate(so, output_schema)
                        break
                    except jsonschema.ValidationError as ve:
                        # 尝试从 schema-echo 包装中救出内层合规对象
                        rescued = self._coerce_schema_echo(so, output_schema)
                        if rescued is not None:
                            logger.info(
                                f"客户端 schema 复核失败但 coerce 成功救回 (第 {attempt + 1} 次): "
                                f"原 so_keys={list(so.keys()) if isinstance(so, dict) else '?'} "
                                f"→ rescued_keys={list(rescued.keys()) if isinstance(rescued, dict) else '?'}"
                            )
                            so = rescued
                            content = json.dumps(so, ensure_ascii=False)
                            break
                        logger.warning(
                            f"客户端 schema 复核失败 (第 {attempt + 1}/{MAX_SCHEMA_RETRIES} 次): "
                            f"{ve.message[:200]} | path={list(ve.absolute_path)} | "
                            f"so_keys={list(so.keys()) if isinstance(so, dict) else type(so).__name__}"
                        )
                        retry_text = self._build_schema_retry_prompt(so, ve, output_schema)
                        retry_payload: dict[str, Any] = {
                            "parts": [{"type": "text", "text": retry_text}],
                            "format": payload["format"],
                        }
                        data, raw_text, parse_err = await self._post_and_parse(
                            session, url, retry_payload, client_timeout
                        )
                        if data is None:
                            logger.warning(f"schema 重试服务端返回非 JSON,放弃: {parse_err}")
                            so, content = None, ""
                            break
                        so, content, tokens, total_tokens = self._extract_outputs(data)
                        if so is None:
                            break
                else:
                    logger.warning(
                        f"客户端 schema 复核 {MAX_SCHEMA_RETRIES} 次后仍失败,丢弃 structured_output"
                    )
                    so, content = None, ""

            return {
                "response": content,
                "usage": tokens,
                "_tokens": total_tokens,
                "structured_output": so,
            }
        except asyncio.TimeoutError:
            raise TimeoutError("Agent HTTP 执行超时")

    async def _post_and_parse(
        self,
        session: aiohttp.ClientSession,
        url: str,
        payload: dict[str, Any],
        client_timeout: aiohttp.ClientTimeout,
    ) -> tuple[dict | None, str, str]:
        """发请求并解析 JSON。失败返回 (None, raw_text, err_msg)。"""
        async with session.post(url, json=payload, timeout=client_timeout) as response:
            if response.status != 200:
                err = await response.text()
                raise RuntimeError(f"OpenCode Server 异常: {err}")
            text = await response.text()
            try:
                return json.loads(text), text, ""
            except json.JSONDecodeError as e:
                return None, text, str(e)

    def _extract_outputs(self, data: dict) -> tuple[Any, str, dict, int]:
        """从 opencode 返回的 {info, parts} 抽 structured_output / content / token 统计。"""
        info = data.get("info", {}) or {}
        parts = data.get("parts", []) or []

        structured_output = None
        for part in parts:
            if part.get("type") == "tool" and part.get("tool") == "StructuredOutput":
                state = part.get("state", {}) or {}
                if state.get("status") == "completed":
                    structured_output = state.get("input")
                    break

        if structured_output is not None:
            content = json.dumps(structured_output, ensure_ascii=False)
        else:
            content = ""
            for part in parts:
                if part.get("type") == "text":
                    content = part.get("text", "")
                    if content:
                        break

        tokens = info.get("tokens") or {}
        total_tokens = tokens.get("total", 0) if isinstance(tokens, dict) else 0
        return structured_output, content, tokens, total_tokens

    @staticmethod
    def _coerce_schema_echo(so: Any, schema: dict) -> Any | None:
        """救回 LLM 把答案塞进 schema-echo 壳子里的情况。

        遇到过的壳子形态:
          A) {"oneOf": "[{...real obj...}]"}              # value 是 JSON-encoded array 字符串
          B) {"oneOf": [{...real branch obj...}]}         # value 是真数组
          C) {"oneOf": [{"properties": {...real fields...}}]}  # 真字段在 properties 嵌套下
          D) {entry_route, ..., call_chain: "[\"1.\",...]"}    # 字段齐但 call_chain 是 stringified array
        从中挑第一个 schema-validate 通过的对象(允许轻度类型修复)返回;失败返回 None。
        """
        if not isinstance(so, dict):
            return None

        # 收集所有候选 dict (任意嵌套深度)
        candidates: list[dict] = []

        def _walk(x: Any) -> None:
            if isinstance(x, str):
                stripped = x.strip()
                if stripped.startswith(("[", "{")):
                    try:
                        _walk(json.loads(stripped))
                    except json.JSONDecodeError:
                        return
            elif isinstance(x, list):
                for item in x:
                    _walk(item)
            elif isinstance(x, dict):
                candidates.append(x)
                # 不仅是 schema-keyword 子壳,任何 value 都可能藏真答案
                for v in x.values():
                    _walk(v)

        _walk(so)

        # 对每个候选先严校,失败做轻度类型修复后再校
        for cand in candidates:
            try:
                jsonschema.validate(cand, schema)
                return cand
            except jsonschema.ValidationError:
                fixed = OpenCodeAgent._light_fix(cand)
                if fixed is not None and fixed != cand:
                    try:
                        jsonschema.validate(fixed, schema)
                        return fixed
                    except jsonschema.ValidationError:
                        continue
        return None

    @staticmethod
    def _light_fix(d: dict) -> dict | None:
        """对接近合规的对象做轻度类型修复。
        - call_chain / historical_chain 是 stringified array → 解析回 list[str]
        - line_number 是数字字符串 → 转 int (schema 允许 [integer,string],但少数实现严格)
        """
        if not isinstance(d, dict):
            return None
        out = dict(d)
        for k in ("call_chain", "historical_chain"):
            v = out.get(k)
            if isinstance(v, str):
                stripped = v.strip()
                if stripped.startswith("["):
                    try:
                        parsed = json.loads(stripped)
                        if isinstance(parsed, list):
                            out[k] = [str(x) for x in parsed]
                            continue
                    except json.JSONDecodeError:
                        pass
                # 退路:按换行 + 序号切
                lines = [line.strip() for line in v.split("\n") if line.strip()]
                if lines:
                    out[k] = lines
        return out

    @staticmethod
    def _build_schema_retry_prompt(
        bad_output: Any, error: jsonschema.ValidationError, schema: dict
    ) -> str:
        """构造一段提示,让 LLM 在同 session 内重新调 StructuredOutput 修正输出。"""
        dump = json.dumps(bad_output, ensure_ascii=False)
        if len(dump) > 800:
            dump = dump[:800] + "...(truncated)"
        keys_preview = (
            list(bad_output.keys())[:8] if isinstance(bad_output, dict)
            else f"<{type(bad_output).__name__}>"
        )
        return (
            "你上一次通过 StructuredOutput 工具提交的 JSON 未通过 schema 校验。\n\n"
            f"被拒绝的输出(顶层 keys = {keys_preview}):\n{dump}\n\n"
            f"失败原因: {error.message[:300]}\n"
            f"违规字段路径: {list(error.absolute_path) or '<root>'}\n\n"
            "请**立刻重新调用 StructuredOutput 工具**,产出严格匹配 schema oneOf 三个分支**之一**的对象。\n"
            "❌ 禁止再次输出含 `oneOf` / `properties` / `required` / `not` / `anyOf` 等 schema 关键字作为 key 的对象 —— "
            "你的答案是 schema 所描述的**值**,不是 schema 本身。"
        )

    async def _retry(
        self,
        session: aiohttp.ClientSession,
        raw_output: str,
        error_msg: str,
        allowed_tools: str
    ) -> dict[str, Any]:
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

    async def get_session_status(self, session_id: str | None = None) -> dict[str, Any]:
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

    async def get_session_messages(self, session_id: str | None = None, limit: int = 50) -> list:
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
