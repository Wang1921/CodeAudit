import json
import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# 默认排除的目录 / 文件 glob：覆盖测试、教学反例、构建产物等"不应判为漏洞"的代码。
# 用 CLI `--exclude` 一次性传给 semgrep，所有规则统一生效（比给 33 个 yaml 逐个加 paths.exclude 简洁）。
#
# ⚠️ semgrep --exclude 语法约束：**不支持 `**` globstar**（v10 baseline 实测过）。
# 用单层目录名（如 "test"）即可匹配任意嵌套位置；用 `*.foo` 匹配文件后缀。
# 旧版用 `**/test/**` 会被当字面量字符串，匹配不到任何路径 → 测试代码全漏到引擎里。
# 维护规则：增加条目时给出"为什么排除"的一行注释；删除条目要确认不会导致工程内真实代码被忽略。
DEFAULT_EXCLUDE_GLOBS = [
    # 测试代码（单元 / 集成 / e2e），漏洞模式多是断言用，不应判 sink
    "test",
    "it",
    "tests",
    "__tests__",
    "playwright",
    # WebGoat 风格的教学反例 / 安全示范目录
    "mitigation",
    "securepasswords",
    # 构建产物 / 第三方
    "target",
    "build",
    ".gradle",
    "node_modules",
    "dist",
    "out",
    # Maven Wrapper 启动器（系统辅助代码，非业务）
    "wrapper",
    # IDE / 工具元数据
    ".idea",
    ".vscode",
]


class SemgrepScanner:
    def __init__(self, target_dir: str, rules_path: str | None = None):
        """
        target_dir:  待扫描的源码目录
        rules_path:  用户指定的 Semgrep 规则路径（可选）

        说明：
        - 若用户指定了自定义规则，则仅使用用户规则，不加载内置规则
        - 若未指定用户规则，则使用项目内置规则（/home/CodeAudit/semgrep_rules/）
        """
        self.target_dir = target_dir

        # 修正内置规则路径计算：从文件所在位置向上两级到项目根目录
        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(script_dir)
        self.builtin_rules_dir = Path(project_root) / "semgrep_rules"

        # 用户指定的规则路径（可能为空）
        if rules_path:
            self._user_rules = [Path(p.strip()) for p in rules_path.split(',')]
        else:
            self._user_rules = None

    def _resolve_config(self, language: str | None = None) -> list | None:
        """返回规则路径列表。有用户规则时只用用户规则，否则用内置规则"""
        configs = []

        # 1. 优先使用用户指定的规则
        if self._user_rules:
            for rule in self._user_rules:
                if rule.exists():
                    configs.append(rule)
                    logger.info(f"添加用户规则: {rule}")
                else:
                    logger.warning(f"用户规则不存在: {rule}")
        # 2. 无用户规则时，使用项目内置规则
        elif self.builtin_rules_dir.exists():
            configs.append(self.builtin_rules_dir)
            logger.info(f"添加内置规则: {self.builtin_rules_dir}")
        else:
            logger.warning(f"内置规则目录不存在: {self.builtin_rules_dir}")

        # 3. 如果没有用户规则，且没有内置规则，则返回空列表
        if not configs:
            logger.warning("没有找到任何有效的规则配置")

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

    def scan(self) -> dict[str, Any]:
        """
        执行 Semgrep 扫描并返回结果
        移除 language 参数，扫描所有规则
        """
        configs = self._resolve_config(None)
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

        # 统一应用排除 glob（替代逐规则文件 paths.exclude，避免规则文件改动放大）
        for glob in DEFAULT_EXCLUDE_GLOBS:
            cmd.extend(["--exclude", glob])

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
            logger.info("Semgrep 扫描完成:")
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

    def _convert_to_sink_format(self, semgrep_output: dict) -> dict[str, Any]:
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

    def _parse_scan_results(self, semgrep_output: dict) -> dict[str, Any]:
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

    def _parse_route_result(self, result: dict) -> dict | None:
        """解析单个 API 路由结果"""
        import re

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

        # 推断 HTTP 方法（依赖 spring-api.yaml message 中的 "注解: $MAPPING" 字段）
        http_method = "GET"
        if "PostMapping" in message or "post" in check_id.lower() or "POST" in message:
            http_method = "POST"
        elif "PutMapping" in message or "put" in check_id.lower() or "PUT" in message:
            http_method = "PUT"
        elif "DeleteMapping" in message or "delete" in check_id.lower() or "DELETE" in message:
            http_method = "DELETE"
        elif "PatchMapping" in message or "patch" in check_id.lower() or "PATCH" in message:
            http_method = "PATCH"

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
        # 示例路径: <project>/user-service/src/main/java/.../UserController.java
        parts = filepath.replace("\\", "/").split("/")
        # 查找包含 service 的目录
        for part in parts:
            if "service" in part.lower():
                return part
        return "main"  # 默认值

    def _parse_single_result(self, result: dict) -> dict:
        """解析单个 Semgrep 结果"""
        path = result.get("path", "")
        line = result.get("start", {}).get("line", 1)
        end_line = result.get("end", {}).get("line", line)
        col = result.get("start", {}).get("col", 1)
        end_col = result.get("end", {}).get("col", 1)

        extra = result.get("extra", {})

        # Semgrep CE 匿名状态下 extra.lines 会被替换为 "requires login";
        # 历史代码把 extra.lines 当 dict 取也是错的(其实是 str)。
        # 兜底:占位/空值时直接读源文件对应行,保证 dangerous_code 永远有内容。
        raw_lines = (extra.get("lines") or "").strip()
        if raw_lines and raw_lines != "requires login":
            code = raw_lines
        else:
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    src_lines = fh.read().splitlines()
                code = "\n".join(src_lines[line - 1:end_line]).strip()
            except OSError:
                code = ""

        metadata = result.get("extra", {}).get("metadata", {})
        vuln_class = self._extract_vuln_class(result, metadata)
        cwe = metadata.get("cwe", "")
        message = result.get("message", "")

        check_id = result.get("check_id", "")
        severity = result.get("extra", {}).get("severity", "ERROR")

        taint_var = self._extract_taint_variable(result, code)

        # taint_required 控制下游分流：
        #   True  (默认) → 走 ReverseTracer → RedValidator → BlueValidator 完整污点链
        #   False         → fast path 直接到 BlueValidator 做静态定性（弱加密/弱随机/硬编码等）
        taint_required = bool(metadata.get("taint_required", True))

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
                "severity": severity,
                "taint_required": taint_required,
            }
        }

    def _extract_vuln_class(self, result: dict, metadata: dict) -> str:
        """从 Semgrep 结果提取漏洞类别（用于全链路 vuln_type 统一命名）。
        优先级：
          1. metadata.vuln_class —— 规则作者手填的标准英文名（如 "SQL Injection"），
             项目自带规则全部带这个字段，LogicAuditor 也复用同一命名空间。
          2. category / technology / subcategory 拼接 —— 外部规则可能只给这些。
          3. check_id —— 兜底（形如 semgrep_rules.custom.java-xxx 的长串，不美观但至少唯一）。
        """
        vuln_class = metadata.get("vuln_class", "")
        if vuln_class:
            return vuln_class

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

        check_id = result.get("check_id", "")
        if check_id:
            return check_id

        return "unknown-vulnerability"

    def _extract_taint_variable(self, result: dict, code: str) -> str:
        """从 Semgrep 结果或 dangerous_code 推断污点变量名(供 LLM 反向追踪)。

        优先级:
          1. Semgrep 命名捕获 extra.metavars 的 $X / $URL 等 (PRO 模式有,CE 匿名通常空)
          2. extra.match 老逻辑 (CE 匿名通常空)
          3. dangerous_code 末尾方法调用的实参列表 (剔除字面量后取前 3 个)
          4. 兜底占位符 — 仅当前 3 步全失败才会落到这里
        """
        try:
            extra = result.get("extra") or {}

            metavars = extra.get("metavars") or {}
            for k, v in metavars.items():
                if not isinstance(k, str) or not k.startswith("$"):
                    continue
                text = v.get("abstract_content") if isinstance(v, dict) else v
                if text:
                    return str(text)[:80]

            match = extra.get("match", "") or ""
            if match:
                variables = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*[,\)]', match)
                if variables:
                    return ", ".join(variables[:3])

            if code:
                args = [a for a in self._extract_call_args(code) if self._is_likely_var(a)]
                if args:
                    return ", ".join(args[:3])

            return "potentially_controlled_input"

        except Exception:
            return "potentially_controlled_input"

    @staticmethod
    def _extract_call_args(code: str) -> list[str]:
        """抽 Java 代码片段最右侧 method(...) 的实参列表;无参时返回 [receiver]。"""
        if "(" not in code or ")" not in code:
            return []
        end = code.rfind(")")
        depth, start = 1, -1
        for i in range(end - 1, -1, -1):
            ch = code[i]
            if ch == ")":
                depth += 1
            elif ch == "(":
                depth -= 1
                if depth == 0:
                    start = i
                    break
        if start < 0:
            return []

        args_str = code[start + 1:end].strip()
        if not args_str:
            m = re.search(
                r"([a-zA-Z_][a-zA-Z0-9_]*)\s*\.\s*[a-zA-Z_][a-zA-Z0-9_]*\s*$",
                code[:start],
            )
            return [m.group(1)] if m else []

        out: list[str] = []
        buf: list[str] = []
        depth = 0
        in_str: str | None = None
        for c in args_str:
            if in_str:
                buf.append(c)
                if c == in_str and (len(buf) < 2 or buf[-2] != "\\"):
                    in_str = None
            elif c in ('"', "'"):
                in_str = c
                buf.append(c)
            elif c == "(":
                depth += 1
                buf.append(c)
            elif c == ")":
                depth -= 1
                buf.append(c)
            elif c == "," and depth == 0:
                out.append("".join(buf))
                buf = []
            else:
                buf.append(c)
        if buf:
            out.append("".join(buf))
        return [a.strip() for a in out if a.strip()]

    @staticmethod
    def _is_likely_var(arg: str) -> bool:
        """排除纯字面量,保留含标识符的任何表达式(包括 \"...\" + var 这种字符串拼接)。"""
        a = arg.strip()
        if not a:
            return False
        if a.lower() in ("true", "false", "null"):
            return False
        if re.match(r"^-?\d+(\.\d+)?[fFlLdD]?$", a):
            return False
        # 剥字符串字面量(支持 \" 转义) + 数字常量,看是否还残留标识符
        stripped = re.sub(
            r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|\b\d+(?:\.\d+)?[fFlLdD]?\b',
            "",
            a,
        )
        return bool(re.search(r"[a-zA-Z_][a-zA-Z0-9_]*", stripped))

    def get_supported_languages(self) -> list[str]:
        """获取支持的语言列表"""
        if self._user_rules:
            return [p.stem for p in self._user_rules]
        return sorted(f.stem for f in self.builtin_rules_dir.glob("*.yaml"))
