import subprocess
import json
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

class SemgrepScanner:
    def __init__(self, target_dir: str, rules_path: Optional[str] = None):
        """
        target_dir:  待扫描的源码目录
        rules_path:  Semgrep 规则路径，支持：
                     - None          → 使用内置 src/semgrep_rules/<language>.yaml
                     - 目录路径      → 直接扫描该目录下所有 .yaml 规则文件（推荐使用 semgrep-rules）
                     - .yaml 文件路径 → 直接作为 --config 传给 semgrep（忽略 language 参数）
        """
        self.target_dir = target_dir
        self._rules_path = Path(rules_path) if rules_path else None
        self.rules_dir = Path(rules_path) if rules_path else Path(__file__).parent / "semgrep_rules"

    def _resolve_config(self, language: Optional[str] = None) -> Optional[Path]:
        """返回实际传给 --config 的路径，不存在则返回 None。"""
        if self._rules_path and self._rules_path.is_file():
            return self._rules_path
        if self._rules_path and self._rules_path.is_dir():
            return self._rules_path
        if language:
            rule_file = self.rules_dir / f"{language}.yaml"
            return rule_file if rule_file.exists() else None
        return None

    def scan(self, language: str = "java") -> Dict[str, Any]:
        """执行 Semgrep 扫描并返回结果"""
        config = self._resolve_config(language)
        if config is None:
            logger.warning(f"规则文件不存在: {self.rules_dir / (language + '.yaml')}")
            return {"sinks": [], "total": 0}

        cmd = [
            "semgrep",
            "--config", str(config),
            "--json",
            "--no-git-ignore",
            "--severity", "ERROR",
            "--severity", "WARNING",
            "--quiet",
            self.target_dir
        ]
        
        logger.info(f"执行 Semgrep 扫描: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=300
            )
            
            if result.returncode != 0:
                logger.error(f"Semgrep 执行失败 (返回码 {result.returncode}): {result.stderr}")
                return {"sinks": [], "total": 0}
            
            if result.stderr:
                logger.warning(f"Semgrep stderr: {result.stderr}")
            
            stdout = result.stdout
            json_start = stdout.find('{')
            json_end = stdout.rfind('}')
            
            if json_start == -1 or json_end == -1:
                logger.error("无法在输出中找到 JSON 数据")
                return {"sinks": [], "total": 0}
            
            json_str = stdout[json_start:json_end + 1]
            semgrep_output = json.loads(json_str)
            
            scan_result = self._convert_to_sink_format(semgrep_output)
            
            total = scan_result.get("total", 0)
            logger.info(f"Semgrep 扫描完成，共发现 {total} 个潜在漏洞点")
            
            for i, sink in enumerate(scan_result.get("sinks", [])[:5]):
                details = sink.get("sink_details", {})
                logger.info(f"  [{i+1}] {details.get('vuln_class')} @ {details.get('filepath')}:{details.get('line_number')}")
            
            if total > 5:
                logger.info(f"  ... 还有 {total - 5} 个漏洞点")
            
            return scan_result
            
        except subprocess.TimeoutExpired:
            logger.error("Semgrep 执行超时（300秒）")
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
        vuln_class = self._extract_vuln_class(result, metadata)
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
    
    def _extract_vuln_class(self, result: Dict, metadata: Dict) -> str:
        """从 Semgrep 结果提取漏洞类别"""
        check_id = result.get("check_id", "")
        if check_id:
            return check_id
        
        category = metadata.get("category", "")
        technology = metadata.get("technology", [])
        subcategory = metadata.get("subcategory", "")
        
        if category:
            if isinstance(technology, list) and technology:
                tech_str = ", ".join(technology[:2])
                if subcategory:
                    return f"{category}.{tech_str}.{subcategory}"
                return f"{category}.{tech_str}"
            if subcategory:
                return f"{category}.{subcategory}"
            return category
        
        return "unknown-vulnerability"
    
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
        if self._rules_path and self._rules_path.is_file():
            return [self._rules_path.stem]
        return sorted(f.stem for f in self.rules_dir.glob("*.yaml"))