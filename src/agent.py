import asyncio
import json
import logging
from typing import Optional, Dict, Any
from src import prompts

class OpenCodeSubprocess:
    def __init__(self, target_source_dir: str, timeout: int = 1800):
        self.target_source_dir = target_source_dir
        self.timeout = timeout

    async def _run_process(self, prompt: str, tools: Optional[str] = None) -> tuple[Optional[int], str, str]:
        import sys
        
        cmd = ["opencode", "run", "--format", "json"]
        if sys.platform == "win32":
            cmd = ["opencode.cmd", "run", "--format", "json"]
        if tools:
            cmd.extend(["--tools", tools])
        
        logging.debug(f"执行命令: {' '.join(cmd[:5])} [stdin-prompt]")
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE,
            cwd=self.target_source_dir
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(input=prompt.encode('utf-8')),
                timeout=self.timeout
            )
            logging.debug(f"进程标准输出: {stdout}")
            logging.debug(f"进程标准错误: {stderr}")
            if stdout:
                stdout_str = stdout.decode('utf-8', errors='ignore')
            else:
                stdout_str = ""
            if stderr:
                stderr_str = stderr.decode('utf-8', errors='ignore')
            else:
                stderr_str = ""
            return process.returncode, stdout_str, stderr_str
        except asyncio.TimeoutError:
            process.kill()
            await process.communicate()
            raise TimeoutError("Agent 执行超时")
        except Exception as e:
            logging.error(f"进程执行失败: {e}")
            raise

    def _extract_json(self, output: str) -> str:
        full_text = ""
        for line in output.strip().split('\n'):
            if not line.strip(): continue
            try:
                data = json.loads(line)
                if data.get('type') == 'text' and 'part' in data and 'text' in data['part']:
                    full_text += data['part']['text']
            except:
                pass
        
        if not full_text:
            full_text = output

        start = full_text.find('{')
        end = full_text.rfind('}')
        if start != -1 and end != -1:
            return full_text[start:end+1]
        return full_text

    async def execute(self, prompt: str, tools: Optional[str] = None) -> Dict[str, Any]:
        """执行 Agent 并返回解析后的 JSON。"""
        _, stdout, _ = await self._run_process(prompt, tools)
        clean_out = self._extract_json(stdout)
        
        try:
            return json.loads(clean_out)
        except json.JSONDecodeError as e:
            logging.warning(f"首次尝试 JSON 解析失败: {e}")
            retry_prompt = prompts.format_retry_prompt(error_details=str(e), raw_output=clean_out)
            _, retry_stdout, _ = await self._run_process(retry_prompt, tools)
            clean_retry = self._extract_json(retry_stdout)
            try:
                return json.loads(clean_retry)
            except json.JSONDecodeError as e2:
                logging.error("重试时 JSON 解析失败")
                raise ValueError(f"Agent 未能返回有效的 JSON。原始输出: {clean_retry}") from e2
