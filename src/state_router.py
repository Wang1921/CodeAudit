import json
import logging
import os
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from src.a2a_bus import A2ABusManager

# 终止状态：Agent 明确声明"无事"。status 一旦命中，链路立即终止。
# 若 Agent 同时返回业务字段（prompt 违规），视为矛盾输出，按 status 裁决，
# 业务字段一律忽略 —— 这是 BlueValidator 以"benchmark/test 代码"洗白真漏洞
# 且 ReverseTracer 偶发给 NOT_EXPLOITABLE + 业务字段的兜底。
TERMINAL_STATES = ("NOT_EXPLOITABLE", "DEFENDED")

# 判定"Agent 其实给了业务信号"的字段集合（仅用于日志诊断）
_BUSINESS_FIELDS = ("vuln_type", "vuln_class", "action", "attack_vector", "mitigation_advice")


@dataclass(frozen=True)
class RouteRule:
    """描述"某个 sender 完成后"的单条路由规则（数据驱动替代原先的 6 个方法）。

    - next_* 为 None 表示这是终点（ReportGenerator）
    - success_add_task=False 表示"同一漏洞在链内接力"（BlueValidator → ReportGenerator）
    - on_success_hook(router, task_id, merged_payload) 用于保留个别副作用（如报告落盘）
    """
    sender: str
    success_check: Callable[[dict[str, Any]], bool]
    next_message_type: str | None = None
    next_recipient: str | None = None
    success_kanban_category: str | None = None          # "red" / "blue" / "resolved"
    success_kanban_status: str = "PENDING"
    success_details_fields: tuple[str, ...] = field(default_factory=tuple)
    success_add_task: bool = True
    miss_kanban_label: str | None = None                # 第一列显示的"类型"
    miss_kanban_reason: str | None = None               # 第二列显示的"原因"
    miss_kanban_status: str = "DEFENDED"
    on_success_hook: Callable[["StateRouter", str, dict[str, Any]], None] | None = None


# 红队/蓝队/报告阶段看板 details 的字段顺序
_RED_DETAILS = ("call_chain", "suspicion_reason", "vuln_type", "entry_route")
_BLUE_DETAILS = (
    "attack_vector", "poc_payload", "max_impact",
    "call_chain", "suspicion_reason", "vuln_type", "entry_route",
)
_RESOLVED_DETAILS = (
    "call_chain", "attack_vector", "defense_analysis", "mitigation_advice",
    "suspicion_reason", "cwe", "poc_payload", "max_impact",
    "vulnerability", "cwe_id", "severity", "description", "remediation",
    "vuln_type", "entry_route",
)


def _has_vuln_type(p: dict[str, Any]) -> bool:
    return bool(p.get("vuln_type") or p.get("vuln_class"))


def _red_hit(p: dict[str, Any]) -> bool:
    return p.get("status") == "EXPLOITABLE" or "attack_vector" in p


def _blue_hit(p: dict[str, Any]) -> bool:
    return p.get("status") == "VULNERABLE" or "mitigation_advice" in p


# ---------- CWE 映射表：vuln_type（Semgrep metadata.vuln_class + LogicAuditor 白名单）→ CWE 编号 ----------
_VULN_TYPE_TO_CWE: dict[str, str] = {
    # 技术类 —— 注入 & RCE
    "SQL Injection": "CWE-89",
    "Command Injection": "CWE-78",
    "Code Injection": "CWE-94",
    "LDAP Injection": "CWE-90",
    "XPath Injection": "CWE-643",
    "NoSQL Injection": "CWE-943",
    "Template Injection": "CWE-94",
    "SpEL Injection": "CWE-917",
    "JNDI Injection": "CWE-74",
    "JDBC URL Injection": "CWE-89",
    "Unsafe Deserialization": "CWE-502",
    "Unsafe Reflection": "CWE-470",
    # 技术类 —— XML / XXE / SSRF
    "XXE": "CWE-611",
    "SSRF": "CWE-918",
    # 技术类 —— 文件路径
    "Path Traversal": "CWE-22",
    "Zip Slip": "CWE-22",
    "Insecure Temp File": "CWE-377",
    # 技术类 —— Web 输出
    "XSS": "CWE-79",
    "Open Redirect": "CWE-601",
    "Unvalidated Forward": "CWE-601",
    # 技术类 —— 加密 / 随机 / 凭据
    "Weak Cryptography": "CWE-327",
    "Weak Random": "CWE-338",
    "Static IV": "CWE-329",
    "Constant Salt": "CWE-760",
    "Hardcoded Credentials": "CWE-798",
    "Insecure TLS": "CWE-295",
    "JWT None Algorithm": "CWE-347",
    # 技术类 —— 会话 / Cookie / 边界
    "Insecure Cookie": "CWE-614",
    "Trust Boundary Violation": "CWE-501",
    # 技术类 —— 信息泄露
    "Stack Trace Exposure": "CWE-209",
    "Sensitive Data in Log": "CWE-532",
    "Sensitive Data in URL": "CWE-598",
    # 业务逻辑类（来自 LogicAuditor 白名单）
    "IDOR": "CWE-639",
    "Missing Authorization": "CWE-862",
    "Privilege Escalation": "CWE-269",
    "Authentication Bypass": "CWE-287",
    "Hardcoded Backdoor": "CWE-798",
    "Mass Assignment": "CWE-915",
    "Workflow Bypass": "CWE-840",
    "Race Condition": "CWE-362",
    "Insufficient Anti-Automation": "CWE-307",
}


# ---------- 默认严重度表：无 payload.severity / max_impact 信号时按类型查表 ----------
_VULN_TYPE_TO_DEFAULT_SEVERITY: dict[str, str] = {
    # Critical —— RCE / 全站认证绕过 / 凭据泄露等零距离 Game Over
    "SQL Injection": "Critical",
    "Command Injection": "Critical",
    "Code Injection": "Critical",
    "SpEL Injection": "Critical",
    "Template Injection": "Critical",
    "NoSQL Injection": "Critical",
    "JNDI Injection": "Critical",
    "JDBC URL Injection": "Critical",
    "Unsafe Deserialization": "Critical",
    "Unsafe Reflection": "Critical",
    "Hardcoded Credentials": "Critical",
    "Hardcoded Backdoor": "Critical",
    # High —— 数据泄露 / 关键认证相关 / MITM / 权限越界
    "XXE": "High",
    "SSRF": "High",
    "Path Traversal": "High",
    "Zip Slip": "High",
    "LDAP Injection": "High",
    "XPath Injection": "High",
    "XSS": "High",
    "Weak Cryptography": "High",
    "Static IV": "High",
    "Constant Salt": "High",
    "JWT None Algorithm": "High",
    "Insecure TLS": "High",
    "Authentication Bypass": "High",
    "Privilege Escalation": "High",
    "IDOR": "High",
    "Mass Assignment": "High",
    "Missing Authorization": "High",
    # Medium —— 影响有条件 / 需社工或配合其它缺陷才成型
    "Weak Random": "Medium",
    "Open Redirect": "Medium",
    "Unvalidated Forward": "Medium",
    "Trust Boundary Violation": "Medium",
    "Insecure Cookie": "Medium",
    "Sensitive Data in Log": "Medium",
    "Sensitive Data in URL": "Medium",
    "Workflow Bypass": "Medium",
    "Race Condition": "Medium",
    "Insufficient Anti-Automation": "Medium",
    # Low —— 仅本地信息泄露 / 辅助性质
    "Stack Trace Exposure": "Low",
    "Insecure Temp File": "Low",
}


def _extract_cwe_id(payload: dict[str, Any]) -> str:
    """按优先级取 CWE 编号：顶层 cwe（已被 _build_merged_payload 从 sink_details.cwe 提升）→ vuln_type 映射。"""
    cwe = payload.get("cwe")
    raw = ""
    if isinstance(cwe, list) and cwe:
        raw = str(cwe[0])
    elif isinstance(cwe, str):
        raw = cwe
    m = re.match(r"(CWE-\d+)", raw)
    if m:
        return m.group(1)
    vt = payload.get("vuln_type") or payload.get("vuln_class") or ""
    return _VULN_TYPE_TO_CWE.get(vt, "")


def _infer_severity(payload: dict[str, Any]) -> str:
    """按优先级定级：payload.severity → max_impact 关键词 → vuln_type 默认表 → Medium 兜底。"""
    # 1) 显式给出的 severity
    sev = payload.get("severity")
    if isinstance(sev, str) and sev:
        sev_up = sev.strip().capitalize()
        if sev_up in ("Critical", "High", "Medium", "Low"):
            return sev_up
    # 2) max_impact 里的强信号关键词
    impact = (payload.get("max_impact") or "").lower()
    if any(k in impact for k in ("rce", "remote code", "任意命令", "任意代码", "任意文件写")):
        return "Critical"
    if any(k in impact for k in ("sql", "数据泄露", "数据泄漏", "data leak", "认证绕过", "越权", "权限提升")):
        return "High"
    # 3) 按 vuln_type 查默认严重度表
    vt = payload.get("vuln_type") or payload.get("vuln_class") or ""
    if vt in _VULN_TYPE_TO_DEFAULT_SEVERITY:
        return _VULN_TYPE_TO_DEFAULT_SEVERITY[vt]
    # 4) 兜底
    return "Medium"


def _build_description(payload: dict[str, Any]) -> str:
    """拼接 suspicion_reason + attack_vector + defense_analysis 为统一描述。"""
    parts = []
    sr = payload.get("suspicion_reason")
    av = payload.get("attack_vector")
    da = payload.get("defense_analysis")
    if sr:
        parts.append(f"[发现] {sr}")
    if av:
        parts.append(f"[攻击面] {av}")
    if da:
        parts.append(f"[防御分析] {da}")
    return "\n\n".join(parts)


def _build_report_fields(payload: dict[str, Any]) -> dict[str, Any]:
    """从 BlueValidator 的 VULNERABLE 输出合成最终报告字段（原 ReportGenerator agent 的纯函数替代）。"""
    return {
        "vuln_type": payload.get("vuln_type") or payload.get("vuln_class") or "未知",
        "cwe_id": _extract_cwe_id(payload),
        "severity": _infer_severity(payload),
        "location": {
            "file": payload.get("filepath", "未知"),
            "line": payload.get("line_number", 0),
        },
        "entry_route": payload.get("entry_route", "未知"),
        "call_chain": payload.get("call_chain", []),
        "description": _build_description(payload),
        "remediation": payload.get("mitigation_advice", ""),
        "attack_vector": payload.get("attack_vector", ""),
        "poc_payload": payload.get("poc_payload", ""),
        "max_impact": payload.get("max_impact", ""),
        "defense_analysis": payload.get("defense_analysis", ""),
        "suspicion_reason": payload.get("suspicion_reason", ""),
    }


_PLACEHOLDER_PATTERN = re.compile(
    r"^\s*(n/?a|无|none|null|不适用|暂无|not\s+applicable|未知|未定|-+)\s*$",
    re.IGNORECASE,
)


def _is_placeholder(text: Any) -> bool:
    """识别 attack_vector / poc_payload / max_impact 里的占位字符串。
    schema 拆 3 变体后这种情况应已不可能（路径 B 禁止这些字段），保留作为防御纵深。"""
    if not isinstance(text, str) or not text.strip():
        return False
    return bool(_PLACEHOLDER_PATTERN.match(text))


def _save_report_hook(router: "StateRouter", task_id: str, payload: dict[str, Any]) -> None:
    """BlueValidator 裁决 VULNERABLE 后的接力钩子：Python 直接组装报告落盘，不再经 LLM。

    防御纵深：若 attack_vector / poc_payload / max_impact 任一为占位字符串（"N/A" 等），
    记 WARNING 并将该字段清空（避免污染 SUMMARY.md），但仍按 VULNERABLE 落盘 —— schema 才是真闸门。
    """
    placeholder_fields = [
        f for f in ("attack_vector", "poc_payload", "max_impact")
        if _is_placeholder(payload.get(f))
    ]
    if placeholder_fields:
        logging.warning(
            f"[BlueValidator] {task_id} status=VULNERABLE 但 {placeholder_fields} 是占位字符串。"
            f"schema oneOf 拆 3 变体后路径 B 应已禁止这些字段——检查 schema 是否生效。"
            f"占位字段已被清空避免污染报告。"
        )
        for f in placeholder_fields:
            payload[f] = ""
    report = _build_report_fields(payload)
    router._save_vulnerability_report(task_id, report)


ROUTE_RULES: dict[str, RouteRule] = {
    "ReverseTracer": RouteRule(
        sender="ReverseTracer",
        success_check=_has_vuln_type,
        next_message_type="VulnCandidate",
        next_recipient="RedValidator",
        success_kanban_category="red",
        success_details_fields=_RED_DETAILS,
        miss_kanban_label="ReverseTracer",
        miss_kanban_reason="输出字段缺失",
    ),
    "LogicAuditor": RouteRule(
        sender="LogicAuditor",
        success_check=lambda p: "vuln_type" in p,
        next_message_type="VulnCandidate",
        next_recipient="RedValidator",
        success_kanban_category="red",
        success_details_fields=_RED_DETAILS,
        miss_kanban_label="LOGIC",
        miss_kanban_reason="审计通过",
    ),
    "RedValidator": RouteRule(
        sender="RedValidator",
        success_check=_red_hit,
        next_message_type="ExploitAttempt",
        next_recipient="BlueValidator",
        success_kanban_category="blue",
        success_details_fields=_BLUE_DETAILS,
        miss_kanban_label="RED-FAIL",
        miss_kanban_reason="不可利用",
    ),
    "BlueValidator": RouteRule(
        sender="BlueValidator",
        success_check=_blue_hit,
        # 报告生成不再走 LLM agent：BlueValidator 裁决 VULNERABLE 后，
        # on_success_hook 在 Python 侧直接组装并落盘报告（字段映射 + CWE 查表）。
        next_message_type=None,
        next_recipient=None,
        success_kanban_category="resolved",
        success_kanban_status="CONFIRMED",
        success_details_fields=_RESOLVED_DETAILS,
        success_add_task=False,
        miss_kanban_label="BLUE-FAIL",
        miss_kanban_reason="防御有效",
        on_success_hook=_save_report_hook,
    ),
    "SemgrepScanner": RouteRule(
        # 语义完整性：SemgrepScanner 的任务由 engine 初始化时直接派发，不会走到 route()
        # 保留占位让未知 sender 检查更严格
        sender="SemgrepScanner",
        success_check=lambda _p: False,
    ),
}


class StateRouter:
    def __init__(self, bus: A2ABusManager, tracker=None):
        self.bus = bus
        self.tracker = tracker

    # ---------- JSON 提取（权威值优先） ----------

    def _extract_parsed(self, agent_output: Any) -> dict[str, Any] | None:
        """提取解析后的 JSON dict。
        1) agent_output["structured_output"]：OpenCode 服务端 JSON Schema 校验通过的权威值
        2) agent_output["response"] 字符串：轻量 JSON / Markdown 代码块
        3) agent_output 本身含业务字段：直接使用（兼容历史）
        失败返回 None，由上层按死信处理。
        """
        if isinstance(agent_output, str):
            return self._parse_json_string(agent_output)
        if not isinstance(agent_output, dict):
            return None

        structured = agent_output.get("structured_output")
        if isinstance(structured, dict):
            return structured

        response = agent_output.get("response")
        if isinstance(response, str) and response.strip():
            parsed = self._parse_json_string(response)
            if parsed is not None:
                return parsed

        if any(k in agent_output for k in (*_BUSINESS_FIELDS, "status")):
            return agent_output

        return None

    @staticmethod
    def _parse_json_string(text: str) -> dict[str, Any] | None:
        """轻量 JSON 提取：严格 parse → raw_decode 容错 → Markdown 代码块。失败返回 None。"""
        text = text.strip()
        if not text:
            return None

        # ❶ 严格：整串必须是合法 JSON
        try:
            parsed = json.loads(text)
            return parsed if isinstance(parsed, dict) else None
        except json.JSONDecodeError:
            pass

        # ❷ 容错：从首个 '{' 开始 greedy 解析一个合法 JSON 对象，
        # 忽略尾部多余字符（如 LLM 偶发输出的 `{...}}` 或 `{...}\n说明...`）
        first_brace = text.find('{')
        if first_brace >= 0:
            try:
                obj, _ = json.JSONDecoder().raw_decode(text[first_brace:])
                if isinstance(obj, dict):
                    return obj
            except json.JSONDecodeError:
                pass

        # ❸ 兜底：Markdown 代码块
        m = re.search(r"```(?:json)?\s*(\{.*?\}|\[.*?\])\s*```", text, re.DOTALL)
        if m:
            try:
                parsed = json.loads(m.group(1))
                return parsed if isinstance(parsed, dict) else None
            except json.JSONDecodeError:
                return None
        return None

    @staticmethod
    def _resolve_entry_route(merged_payload: dict[str, Any]) -> str:
        """统一的 entry_route 提取：agent 自报 → sink_details.filepath → route_details.path。"""
        if merged_payload.get("entry_route"):
            return merged_payload["entry_route"]
        sink = merged_payload.get("sink_details") or {}
        if sink.get("filepath"):
            return sink["filepath"]
        route = merged_payload.get("route_details") or {}
        if route.get("path"):
            return route["path"]
        return "未知"

    # ---------- 主路由入口 ----------

    def route(self, completed_task: str, agent_output: dict[str, Any]):
        """将 Agent 的输出路由到下一跳。"""
        orig_env = self.bus.read_message(completed_task)
        sender = orig_env["recipient"]
        task_id = orig_env["task_id"]

        parsed = self._extract_parsed(agent_output)
        logging.info(
            f"[路由] {sender} | task_id={task_id} | "
            f"parsed_keys={list(parsed.keys()) if parsed else None}"
        )

        # 解析失败：兜底记录，避免任务静默消失
        if not parsed:
            logging.warning(f"[路由] {sender} 任务 {task_id} 输出无法解析为 JSON，丢弃路由")
            if self.tracker:
                self.tracker.update_kanban("resolved", task_id, sender, "无效输出", status="DEFENDED")
            return

        # 特判 1：终态。status 显式裁决优先级最高，链路立即终止。
        # 若 Agent 同时返回业务字段，视为 prompt 违规的矛盾输出，业务字段忽略。
        status = parsed.get("status")
        if status in TERMINAL_STATES:
            has_business = any(k in parsed for k in _BUSINESS_FIELDS)
            if has_business:
                logging.warning(
                    f"[路由] {sender} 任务 {task_id} 矛盾输出：status={status} 同时携带业务字段 "
                    f"{[k for k in _BUSINESS_FIELDS if k in parsed]}。按 status 终止，业务字段忽略。"
                )
            else:
                logging.info(f"任务 {task_id} 达到终态: {status}")
            if self.tracker:
                rule = ROUTE_RULES.get(sender)
                label = (rule.miss_kanban_label if rule else sender) or sender
                reason = (rule.miss_kanban_reason if rule else status) or status
                self.tracker.update_kanban("resolved", task_id, label, reason, status=status)
            return

        # 特判 2：跨微服务追踪求救 —— 必须是"真"跨服务场景，避免 LLM echo action 导致误 fan-out。
        # 成立条件：action=cross_service_trace + 必填的 protocol + target_identifier，
        # 同时不得附带场景 A 的业务字段（call_chain / entry_route）。
        # 业务字段存在意味着本地追踪已经产出结果，没必要再跨服务 hop。
        if (
            sender == "ReverseTracer"
            and parsed.get("action") == "cross_service_trace"
            and parsed.get("protocol")
            and parsed.get("target_identifier")
            and not parsed.get("call_chain")
            and not parsed.get("entry_route")
        ):
            self._route_cross_service_request(task_id, parsed, orig_env)
            return

        # 若 LLM 输出 action=cross_service_trace 但同时有 call_chain/entry_route（常见的 echo 污染），
        # 说明它实际走的是场景 A，只是顺手 echo 了 action 字段。
        # 必须清洗掉场景 B 专有字段（action / protocol / target_identifier / taint_variable / historical_chain），
        # 否则 RedValidator 看到矛盾输入会判 NOT_EXPLOITABLE，导致真漏洞丢失。
        if sender == "ReverseTracer" and parsed.get("action") == "cross_service_trace":
            b_only = [k for k in ("action", "protocol", "target_identifier", "taint_variable", "historical_chain") if k in parsed]
            logging.warning(
                f"[路由] {sender} 任务 {task_id} 输出 action=cross_service_trace 但附带业务字段"
                f"（call_chain/entry_route 存在），视为 echo 污染。清洗场景 B 字段 {b_only} 后按场景 A 正常派发。"
            )
            for k in b_only:
                parsed.pop(k, None)

        rule = ROUTE_RULES.get(sender)
        if rule is None:
            logging.warning(f"未知的发送者: {sender}")
            return
        self._apply_rule(rule, task_id, parsed, orig_env)

    # ---------- 通用规则应用 ----------

    @staticmethod
    def _build_merged_payload(
        orig_payload: dict[str, Any], parsed: dict[str, Any]
    ) -> dict[str, Any]:
        """合并 orig payload + agent 输出，同时清洗"噪声"子结构。

        - sink_details / route_details 只是 SemgrepScanner 给首跳 Agent 的原始数据，
          后续 Agent 已经把关键字段扁平化到顶层（vuln_type / filepath / line_number / ...），
          保留在 payload 里反而让下游 LLM 同时看到两套同名字段容易混淆。
        - 但 sink_details.cwe 是 ReportGenerator 的 cwe_id 来源，需提升到顶层 `cwe` 字段
          以便后续所有跳都能访问。
        - vuln_type 以**上游权威值为准**：sink_details.vuln_class 或上一跳 merged_payload
          里已校准过的 vuln_type；LLM 输出若改写（如把 'SSRF' 写成 'CWE-918: ...'）会被覆盖。
        """
        # 1. 先识别上游权威 vuln_type（用于覆盖 LLM 偏离的输出）
        orig_sink = orig_payload.get("sink_details") or {}
        upstream_vt = (
            orig_sink.get("vuln_class")
            or orig_payload.get("vuln_type")
            or orig_payload.get("vuln_class")
        )

        # 2. 标准合并：parsed 字段覆盖 orig
        merged: dict[str, Any] = {**orig_payload, **parsed}

        # 3. 强制还原 vuln_type 到上游权威值
        if upstream_vt:
            agent_vt = merged.get("vuln_type")
            if agent_vt and agent_vt != upstream_vt:
                logging.warning(
                    f"[normalize] vuln_type 偏离上游权威值："
                    f"agent='{agent_vt}' → 强制还原为 '{upstream_vt}'"
                )
            merged["vuln_type"] = upstream_vt

        # 4. cwe 信息从 sink_details 提升到顶层
        sink = merged.get("sink_details")
        if isinstance(sink, dict):
            if "cwe" not in merged and sink.get("cwe"):
                merged["cwe"] = sink["cwe"]
            merged.pop("sink_details", None)

        # 5. route_details 不再传给下游 Agent（顶层 entry_route / filepath 已承载需要的信息）
        merged.pop("route_details", None)

        return merged

    def _apply_rule(
        self,
        rule: RouteRule,
        task_id: str,
        parsed: dict[str, Any],
        orig_env: dict[str, Any],
    ) -> None:
        merged_payload = self._build_merged_payload(
            orig_env.get("payload", {}) or {}, parsed
        )

        if not rule.success_check(parsed):
            if self.tracker and rule.miss_kanban_label:
                self.tracker.update_kanban(
                    "resolved",
                    task_id,
                    rule.miss_kanban_label,
                    rule.miss_kanban_reason or "",
                    status=rule.miss_kanban_status,
                )
            return

        # 命中路径
        entry_route = self._resolve_entry_route(merged_payload)
        vuln_type = merged_payload.get("vuln_type") or merged_payload.get("vuln_class") or "未知"

        if self.tracker and rule.success_add_task:
            self.tracker.add_task()

        if self.tracker and rule.success_kanban_category:
            details = {f: merged_payload.get(f) for f in rule.success_details_fields}
            self.tracker.update_kanban(
                rule.success_kanban_category,
                task_id,
                vuln_type,
                entry_route,
                status=rule.success_kanban_status,
                details=details,
            )

        if rule.next_recipient and rule.next_message_type:
            # 链路续接（Reverse→Red→Blue 等）走 high 优先级（help_req_dir），
            # 避免跟初始 Semgrep 批量派发的任务挤一个 FIFO 队列被饿死。
            # 实测：WebGoat 1.5h 跑了 100 初始任务，6 条 RedValidator 接力消息全部
            # 卡在 pending → processing 队尾从未被 pickup → 0 个完整污点链落盘。
            self.bus.write_message(
                message_type=rule.next_message_type,
                task_id=task_id,
                sender=rule.sender,
                recipient=rule.next_recipient,
                payload=merged_payload,
                priority="high",
            )

        if rule.on_success_hook is not None:
            try:
                rule.on_success_hook(self, task_id, merged_payload)
            except Exception as e:
                logging.error(f"on_success_hook({rule.sender}) 执行失败: {e}", exc_info=True)

    # ---------- 特判：跨微服务追踪 ----------

    def _route_cross_service_request(
        self, task_id: str, parsed: dict[str, Any], orig_env: dict[str, Any]
    ) -> None:
        """将跨微服务追踪请求路由给 Orchestrator（引擎主循环特殊处理）。"""
        target = parsed.get("target_identifier", "unknown")
        logging.info(f"触发跨微服务追踪求救信号: {task_id} -> 目标: {target}")

        if self.tracker:
            self.tracker.add_task()
            self.tracker.update_kanban("suspicious", f"{task_id}_CROSS", "CROSS_SERVICE", target)

        self.bus.write_message(
            message_type="CrossServiceTraceRequest",
            task_id=f"{task_id}_CROSS",
            sender="ReverseTracer",
            recipient="Orchestrator",
            payload=parsed,
            priority="high",
        )

    # ---------- 终点副作用：报告落盘 ----------

    def _save_vulnerability_report(self, task_id: str, report_fields: dict[str, Any]) -> None:
        """写漏洞报告到 reports/ 目录。report_fields 由 _build_report_fields 映射好，函数只负责落盘。"""
        try:
            output_dir = "reports"
            os.makedirs(output_dir, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = os.path.join(output_dir, f"vulnerability_{task_id}_{timestamp}.json")

            full_report = {
                "task_id": task_id,
                "timestamp": datetime.now().isoformat(),
                **report_fields,
            }

            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(full_report, f, ensure_ascii=False, indent=2)

            logging.info(f"漏洞报告已保存到: {filepath}")
        except Exception as e:
            logging.error(f"保存漏洞报告失败: {e}")
