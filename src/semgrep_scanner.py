import subprocess
import json
import logging
import os
from typing import Dict, Any, List, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

class SemgrepScanner:
    def __init__(self, target_dir: str, rules_path: Optional[str] = None):
        """
        target_dir:  待扫描的源码目录
        rules_path:  用户指定的 Semgrep 规则路径（可选）
        
        说明：
        - 项目内置的自定义规则（/home/CodeAudit/semgrep_rules/）始终会被包含
        - 用户可以额外指定外部规则进行补充（逗号分隔多个）
        """
        self.target_dir = target_dir
        
        # 修正内置规则路径计算：从文件所在位置向上两级到项目根目录
        import os
        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(script_dir)
        self.builtin_rules_dir = Path(project_root) / "semgrep_rules"
        
        # 用户指定的规则路径（可能为空）
        if rules_path:
            self._user_rules = [Path(p.strip()) for p in rules_path.split(',')]
        else:
            self._user_rules = None
    
    def _resolve_config(self, language: Optional[str] = None) -> Optional[list]:
        """返回规则路径列表，始终包含项目内置规则并去重"""
        configs = []
        
        # 1. 首先添加用户指定的规则（如果有）
        if self._user_rules:
            for rule in self._user_rules:
                if rule.exists():
                    configs.append(rule)
                    logger.info(f"添加用户规则: {rule}")
                else:
                    logger.warning(f"用户规则不存在: {rule}")
        
        # 2. 始终添加项目内置的自定义规则（如果存在）
        if self.builtin_rules_dir.exists():
            configs.append(self.builtin_rules_dir)
            logger.info(f"添加内置规则: {self.builtin_rules_dir}")
        else:
            logger.warning(f"内置规则目录不存在: {self.builtin_rules_dir}")
        
        # 3. 如果没有用户规则，且没有内置规则，则尝试语言特定规则
        if not configs and language:
            rule_file = self.builtin_rules_dir / f"{language}.yaml"
            if rule_file.exists():
                configs = [rule_file]
                logger.info(f"添加语言特定规则: {rule_file}")
        
        # 4. 去重（避免用户规则与内置规则重复）
        unique_configs = []
        seen = set()
        for config in configs:
            config_str = str(config)
            if config_str not in seen:
                seen.add(config_str)
                unique_configs.append(config)
            else:
                logger.debug(f"跳过重复规则: {config_str}")
        
        logger.info(f"去重后的规则数量: {len(unique_configs)}")
        for i, config in enumerate(unique_configs):
            logger.info(f"  [{i+1}] {config}")
        
        return unique_configs
 
    def scan(self, language: str = "java") -> Dict[str, Any]:
        """执行 Semgrep 扫描并返回结果"""
        configs = self._resolve_config(language)
        if not configs or len(configs) == 0:
            logger.warning(f"规则文件不存在: {self.builtin_rules_dir}")
            return {"routes": [], "sinks": [], "total_routes": 0, "total_sinks": 0}
 
        cmd = [
            "semgrep",
            "--json",
            self.target_dir
        ]
        
        # 添加多个 --config 参数
        for config in configs:
            cmd.extend(["--config", str(config)])
 
        logger.info(f"执行 Semgrep 扫描: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=1200
            )
            
            if result.returncode != 0:
                logger.error(f"Semgrep 执行失败 (返回码 {result.returncode}): {result.stderr}")
                return {"routes": [], "sinks": [], "total_routes": 0, "total_sinks": 0}
            
            if result.stderr:
                logger.warning(f"Semgrep stderr: {result.stderr}")
            
            stdout = result.stdout
            json_start = stdout.find('{')
            json_end = stdout.rfind('}')
            
            if json_start == -1 or json_end == -1:
                logger.error("无法在输出中找到 JSON 数据")
                return {"routes": [], "sinks": [], "total_routes": 0, "total_sinks": 0}
            
            json_str = stdout[json_start:json_end + 1]
            semgrep_output = json.loads(json_str)
            
            logger.info(f"Semgrep 原始结果数量: {len(semgrep_output.get('results', []))}")
            for i, r in enumerate(semgrep_output.get('results', [])[:3]):
                logger.info(f"  [{i+1}] check_id={r.get('check_id')}, message={r.get('extra', {}).get('message', '')}")
            
            scan_result = self._parse_scan_results(semgrep_output)
            
            total_routes = scan_result.get("total_routes", 0)
            total_sinks = scan_result.get("total_sinks", 0)
            logger.info(f"Semgrep 扫描完成:")
            logger.info(f"  - 发现 {total_routes} 个 API 路由")
            logger.info(f"  - 发现 {total_sinks} 个潜在漏洞点")
            
            # 显示前 5 个路由
            for i, route in enumerate(scan_result.get("routes", [])[:5]):
                logger.info(f"  [{i+1}] {route.get('method', 'UNKNOWN')} {route.get('path', 'unknown-path')} @ {route.get('handler_file', 'unknown-file')}")
            
            # 显示前 5 个漏洞点
            for i, sink in enumerate(scan_result.get("sinks", [])[:5]):
                details = sink.get("sink_details", {})
                logger.info(f"  [{i+1}] {details.get('vuln_class')} @ {details.get('filepath')}:{details.get('line_number')}")
            
            if total_routes > 5:
                logger.info(f"  ... 还有 {total_routes - 5} 个路由")
            if total_sinks > 5:
                logger.info(f"  ... 还有 {total_sinks - 5} 个漏洞点")
            
            return scan_result
            
        except subprocess.TimeoutExpired:
            logger.error("Semgrep 执行超时（300秒）")
            return {"routes": [], "sinks": [], "total_routes": 0, "total_sinks": 0}
        except json.JSONDecodeError as e:
            logger.error(f"解析 Semgrep 输出失败: {e}")
            return {"routes": [], "sinks": [], "total_routes": 0, "total_sinks": 0}
        except Exception as e:
            logger.error(f"Semgrep 执行异常: {e}")
            return {"routes": [], "sinks": [], "total_routes": 0, "total_sinks": 0}
    
    def _convert_to_sink_format(self, semgrep_output: Dict) -> Dict[str, Any]:
        """转换 Semgrep 输出为 SinkHunter 格式（兼容旧接口）"""
        sinks = []
        
        for result in semgrep_output.get("results", []):
            try:
                sink = self._parse_single_result(result)
                if sink:
                    sinks.append(sink)
            except Exception as e:
                logger.warning(f"解析单个结果失败: {e}")
                continue
        
        return {
            "routes": [],
            "sinks": sinks,
            "total_routes": 0,
            "total_sinks": len(sinks)
        }
    
    def _parse_scan_results(self, semgrep_output: Dict) -> Dict[str, Any]:
        """分类解析 Semgrep 结果：区分路由和漏洞点"""
        routes = []
        sinks = []
        
        for result in semgrep_output.get("results",[]):
            try:
                check_id = result.get("check_id", "")
                
                # 根据规则 ID 判断类型（规则 ID 包含 route, api 即为路由）
                if "route" in check_id.lower() or "api" in check_id.lower():
                    route = self._parse_route_result(result)
                    if route:
                        routes.append(route)
                else:
                    sink = self._parse_single_result(result)
                    if sink:
                        sinks.append(sink)
            except Exception as e:
                logger.warning(f"解析单个结果失败: {e}")
                continue
        
        return {
            "routes": routes,
            "sinks": sinks,
            "total_routes": len(routes),
            "total_sinks": len(sinks)
        }
    
    def _parse_route_result(self, result: Dict) -> Optional[Dict]:
        """解析单个 API 路由结果"""
        import re
        import os
        
        message = result.get("extra", {}).get("message", "")
        check_id = result.get("check_id", "")
        path = result.get("path", "")
        line = result.get("start", {}).get("line", 1)
        
        # 将相对路径转换为绝对路径
        if not os.path.isabs(path):
            path = os.path.abspath(os.path.join(self.target_dir, path))
        
        # 从 message 中提取路由信息
        # 示例: "发现 API (带类前缀) -> 类基础路径: "/api", 方法路径: "/eval", 方法名: evaluate"
        base_path_match = re.search(r'类基础路径:\s*"?([^",\s]+)"?', message)
        method_path_match = re.search(r'方法路径:\s*"?([^",\s]+)"?', message)
        method_name_match = re.search(r'方法名:\s*(\w+)', message)
        
        base_path = base_path_match.group(1) if base_path_match else ""
        method_path = method_path_match.group(1) if method_path_match else ""
        method_name = method_name_match.group(1) if method_name_match else "unknown"
        
        # 推断 HTTP 方法
        http_method = "GET"
        if "post" in check_id.lower() or "PostMapping" in message or "POST" in message:
            http_method = "POST"
        elif "put" in check_id.lower() or "PutMapping" in message or "PUT" in message:
            http_method = "PUT"
        elif "delete" in check_id.lower() or "DeleteMapping" in message or "DELETE" in message:
            http_method = "DELETE"
        
        # 推断微服务名称（从文件路径提取）
        owning_service = self._extract_service_name(path)
        
        return {
            "method": http_method,
            "path": base_path + method_path,
            "handler_file": path,
            "handler_line": line,
            "method_name": method_name,
            "owning_service": owning_service
        }
    
    def _extract_service_name(self, filepath: str) -> str:
        """从文件路径提取微服务名称"""
        # 示例路径: dummy_project/user-service/src/main/java/.../UserController.java
        parts = filepath.replace("\\", "/").split("/")
        # 查找包含 service 的目录
        for part in parts:
            if "service" in part.lower():
                return part
        return "main"  # 默认值
    
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
        if self._user_rules:
            return [p.stem for p in self._user_rules]
        return sorted(f.stem for f in self.builtin_rules_dir.glob("*.yaml"))
