import asyncio
import json
import logging
from typing import Optional, Dict, Any
from src.prompts import RETRY_PROMPT

class OpenCodeSubprocess:
    def __init__(self, target_source_dir: str, timeout: int = 1800):
        self.target_source_dir = target_source_dir
        self.timeout = timeout

    async def _run_process(self, prompt: str, tools: Optional[str] = None) -> tuple[Optional[int], str, str]:
        cmd = ["opencode", "run", "--format", "json"]
        if tools:
            pass # opencode handles tools automatically based on the agent or context, we pass prompt as arg
            
        cmd.append(prompt)
        logging.debug(f"Executing command: {' '.join(cmd)}")
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=self.target_source_dir
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.timeout
            )
            logging.debug(f"Process stdout: {stdout}")
            logging.debug(f"Process stderr: {stderr}")
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
            raise TimeoutError("Agent execution timed out")
        except Exception as e:
            logging.error(f"Process execution failed: {e}")
            raise

    def _extract_json(self, output: str) -> str:
        # opencode run --format json might output JSON lines
        # We need to extract the actual text from the parts
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

        # Simple heuristic to extract JSON if there's markdown or extra text
        start = full_text.find('{')
        end = full_text.rfind('}')
        if start != -1 and end != -1:
            return full_text[start:end+1]
        return full_text

    async def execute(self, prompt: str, tools: Optional[str] = None) -> Dict[str, Any]:
        """Execute the agent and return parsed JSON."""
        _, stdout, _ = await self._run_process(prompt, tools)
        clean_out = self._extract_json(stdout)
        
        try:
            return json.loads(clean_out)
        except json.JSONDecodeError as e:
            logging.warning(f"JSON decode failed on first attempt: {e}")
            # Retry mechanism
            retry_prompt = RETRY_PROMPT.format(error_details=str(e), raw_output=clean_out)
            # Send the retry prompt
            _, retry_stdout, _ = await self._run_process(retry_prompt, tools)
            clean_retry = self._extract_json(retry_stdout)
            try:
                return json.loads(clean_retry)
            except json.JSONDecodeError as e2:
                logging.error("JSON decode failed on retry")
                raise ValueError(f"Agent failed to return valid JSON. Raw output: {clean_retry}") from e2
