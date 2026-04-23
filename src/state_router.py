import logging
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, Optional, Tuple

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
    success_check: Callable[[Dict[str, Any]], bool]
    next_message_type: Optional[str] = None
    next_recipient: Optional[str] = None
    success_kanban_category: Optional[str] = None          # "red" / "blue" / "resolved"
    success_kanban_status: str = "PENDING"
    success_details_fields: Tuple[str, ...] = field(default_factory=tuple)
    success_add_task: bool = True
    miss_kanban_label: Optional[str] = None                # 第一列显示的"类型"
    miss_kanban_reason: Optional[str] = None               # 第二列显示的"原因"
    miss_kanban_status: str = "DEFENDED"
    on_success_hook: Optional[Callable[["StateRouter", str, Dict[str, Any]], None]] = None


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


def _has_vuln_type(p: Dict[str, Any]) -> bool:
    return bool(p.get("vuln_type") or p.get("vuln_class"))


def _red_hit(p: Dict[str, Any]) -> bool:
    return p.get("status") == "EXPLOITABLE" or "attack_vector" in p


def _blue_hit(p: Dict[str, Any]) -> bool:
    return p.get("status") == "VULNERABLE" or "mitigation_advice" in p


def _save_report_hook(router: "StateRouter", task_id: str, payload: Dict[str, Any]) -> None:
    router._save_vulnerability_report(task_id, payload)


ROUTE_RULES: Dict[str, RouteRule] = {
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
        next_message_type="ConfirmedVuln",
        next_recipient="ReportGenerator",
        success_kanban_category="resolved",
        success_kanban_status="CONFIRMED",
        success_details_fields=_RESOLVED_DETAILS,
        success_add_task=False,  # 接力同一漏洞，不再增加任务计数
        miss_kanban_label="BLUE-FAIL",
        miss_kanban_reason="防御有效",
    ),
    "ReportGenerator": RouteRule(
        sender="ReportGenerator",
        success_check=lambda _p: True,
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

    def _extract_parsed(self, agent_output: Any) -> Optional[Dict[str, Any]]:
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
    def _parse_json_string(text: str) -> Optional[Dict[str, Any]]:
        """轻量 JSON 提取：直接 parse → Markdown 代码块。失败返回 None。"""
        text = text.strip()
        if not text:
            return None

        try:
            parsed = json.loads(text)
            return parsed if isinstance(parsed, dict) else None
        except json.JSONDecodeError:
            pass

        m = re.search(r"```(?:json)?\s*(\{.*?\}|\[.*?\])\s*```", text, re.DOTALL)
        if m:
            try:
                parsed = json.loads(m.group(1))
                return parsed if isinstance(parsed, dict) else None
            except json.JSONDecodeError:
                return None
        return None

    @staticmethod
    def _resolve_entry_route(merged_payload: Dict[str, Any]) -> str:
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

    def route(self, completed_task: str, agent_output: Dict[str, Any]):
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

        # 特判 1：跨微服务追踪求救 —— 走 Orchestrator 而不是正常路由表
        if sender == "ReverseTracer" and parsed.get("action") == "cross_service_trace":
            self._route_cross_service_request(task_id, parsed, orig_env)
            return

        # 特判 2：终态。status 显式裁决优先级最高，链路立即终止。
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

        rule = ROUTE_RULES.get(sender)
        if rule is None:
            logging.warning(f"未知的发送者: {sender}")
            return
        self._apply_rule(rule, task_id, parsed, orig_env)

    # ---------- 通用规则应用 ----------

    def _apply_rule(
        self,
        rule: RouteRule,
        task_id: str,
        parsed: Dict[str, Any],
        orig_env: Dict[str, Any],
    ) -> None:
        merged_payload = {**orig_env.get("payload", {}), **parsed}

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
            self.bus.write_message(
                message_type=rule.next_message_type,
                task_id=task_id,
                sender=rule.sender,
                recipient=rule.next_recipient,
                payload=merged_payload,
            )

        if rule.on_success_hook is not None:
            try:
                rule.on_success_hook(self, task_id, merged_payload)
            except Exception as e:
                logging.error(f"on_success_hook({rule.sender}) 执行失败: {e}", exc_info=True)

    # ---------- 特判：跨微服务追踪 ----------

    def _route_cross_service_request(
        self, task_id: str, parsed: Dict[str, Any], orig_env: Dict[str, Any]
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

    def _save_vulnerability_report(self, task_id: str, payload: Dict[str, Any]) -> None:
        try:
            output_dir = "reports"
            os.makedirs(output_dir, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = os.path.join(output_dir, f"vulnerability_{task_id}_{timestamp}.json")

            report = {
                "task_id": task_id,
                "timestamp": datetime.now().isoformat(),
                "vuln_type": payload.get("vuln_type", "未知"),
                "entry_route": payload.get("entry_route", "未知"),
                "mitigation_advice": payload.get("mitigation_advice", ""),
                "description": payload.get("description", ""),
                "severity": payload.get("severity", ""),
                "cwe_id": payload.get("cwe_id", ""),
                "poc_payload": payload.get("poc_payload", ""),
                "max_impact": payload.get("max_impact", ""),
                "defense_analysis": payload.get("defense_analysis", ""),
                "remediation": payload.get("remediation", ""),
                "attack_vector": payload.get("attack_vector", ""),
                "call_chain": payload.get("call_chain", []),
                "suspicion_reason": payload.get("suspicion_reason", ""),
                "cwe": payload.get("cwe", ""),
                "vulnerability": payload.get("vulnerability", ""),
            }

            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=2)

            logging.info(f"漏洞报告已保存到: {filepath}")
        except Exception as e:
            logging.error(f"保存漏洞报告失败: {e}")
