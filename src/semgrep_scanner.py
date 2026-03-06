import subprocess
import json
import logging
from typing import Dict, Any, List
from pathlib import Path

logger = logging.getLogger(__name__)

class SemgrepScanner:
    def __init__(self, target_dir: str, rules_dir: str = None):
        self.target_dir = target_dir
        if rules_dir is None:
            rules_dir = str(Path(__file__).parent / "semgrep_rules")
        self.rules_dir = Path(rules_dir)
    
    def scan(self, language: str = "java") -> Dict[str, Any]:
        """执行 Semgrep 扫描并返回结果"""
        rule_file = self.rules_dir / f"{language}.yaml"
        
        if not rule_file.exists():
            logger.warning(f"规则文件不存在: {rule_file}")
            return {"sinks": [], "total": 0}
        
        cmd = [
            "semgrep",
            "--config", str(rule_file),
            "--json",
            "--no-git-ignore",
            "--severity", "ERROR",
            "--severity",            "WARNING",
            "--quiet",
            self.target_dir
        ]
        
        try:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=300
            )
            
            if result.returncode != 0:
                logger.error(f"Semgrep 执行失败: {result.stderr}")
                return {"sinks": [], "total": 0}
            
            stdout = result.stdout
            json_start = stdout.find('{')
            json_end = stdout.rfind('}')
            
            if json_start == -1 or json_end == -1:
                logger.error("无法在输出中找到 JSON 数据")
                return {"sinks": [], "total": 0}
            
            json_str = stdout[json_start:json_end + 1]
            semgrep_output = json.loads(json_str)
            return self._convert_to_sink_format(semgrep_output)
            
        except subprocess.TimeoutExpired:
            logger.error("Semgrep 执行超时")
            return {"sinks": [], "total": 0}
        except json.JSONDecodeError as e:
            logger.error(f"解析 Semgrep 输出失败: {e}")
            return {"sinks": [], "total": 0}
        except Exception as e:
            logger.error(f"Semgrep 执行异常: {e}")
            return {"sinks": [], "total": 0}
    
    def _convert_to_sink_format(self, semgrep_output: Dict) -> Dict[str, Any]:
        """转换 Semgrep 输出为 SinkHunter 格式"""
        sinks = []
        
        for result in semgrep_output.get("results", []):
            try:
                sink = self._parse_single_result(result)
                if sink:
                    sinks.append(sink)
            except Exception as e:
                logger.warning(f"解析单个结果失败: {e}")
                continue
        
        return {"sinks": sinks, "total": len(sinks)}
    
    def _parse_single_result(self, result: Dict) -> Dict:
        """解析单个 Semgrep 结果"""
        path = result.get("path", "")
        line = result.get("start", {}).get("line", 1)
        end_line = result.get("end", {}).get("line", line)
        col = result.get("start", {}).get("col", 1)
        end_col = result.get("end", {}).get("col", 1)
        
        extra = result.get("extra", {})
        lines = extra.get("lines", {})
        
        code = ""
        for line_num in range(line, end_line + 1):
            if str(line_num) in lines:
                code += lines[str(line_num)] + "\n"
        code = code.strip()
        
        metadata = result.get("extra", {}).get("metadata", {})
        vuln_class = metadata.get("vuln_class", "Unknown Vulnerability")
        cwe = metadata.get("cwe", "")
        message = result.get("message", "")
        
        check_id = result.get("check_id", "")
        severity = result.get("extra", {}).get("severity", "ERROR")
        
        taint_var = self._extract_taint_variable(result, code)
        
        return {
            "sink_details": {
                "vuln_class": vuln_class,
                "filepath": path,
                "line_number": line,
                "end_line": end_line,
                "column": col,
                "end_column": end_col,
                "dangerous_code": code,
                "taint_variable": taint_var,
                "cwe": cwe,
                "message": message,
                "check_id": check_id,
                "severity": severity
            }
        }
    
    def _extract_taint_variable(self, result: Dict, code: str) -> str:
        """从 Semgrep 结果推断污点变量"""
        try:
            match = result.get("extra", {}).get("match", "")
            
            if match:
                import re
                var_pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*[,\)]'
                variables = re.findall(var_pattern, match)
                if variables:
                    return ", ".join(variables[:3])
            
            return "potentially_controlled_input"
            
        except Exception:
            return "potentially_controlled_input"
    
    def get_supported_languages(self) -> List[str]:
        """获取支持的语言列表"""
        languages = []
        for file in self.rules_dir.glob("*.yaml"):
            languages.append(file.stem)
        return sorted(languages)