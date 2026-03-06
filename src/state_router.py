import logging
from src.a2a_bus import A2ABusManager
from typing import Dict, Any

NEXT_HOP_ROUTING = {
    "System": {
        "TaskRequest": "Coordinator"
    },
    "Coordinator": {
        "Coordinator_Output": "Fan-out (SemgrepScanner + LogicAuditor)"
    },
    "SemgrepScanner": {
        "ScanResult": "ReverseTracer"
    },
    "ReverseTracer": {
        "VulnCandidate": "RedValidator"
    },
    "LogicAuditor": {
        "VulnCandidate": "RedValidator"
    },
    "RedValidator": {
        "ExploitAttempt": "BlueValidator"
    },
    "BlueValidator": {
        "ConfirmedVuln": "ReportGenerator"
    }
}

TERMINAL_STATES = [
    "NOT_EXPLOITABLE",
    "DEFENDED"
]

class StateRouter:
    def __init__(self, bus: A2ABusManager, tracker=None):
        self.bus = bus
        self.tracker = tracker

    def route(self, completed_task: str, agent_output: Dict[str, Any]):
        """将 Agent 的输出路由到下一跳。"""
        orig_env = self.bus.read_message(completed_task)
        sender = orig_env["recipient"]
        task_id = orig_env["task_id"]
        message_type = orig_env.get("message_type", "TaskRequest")

        status = agent_output.get("status")
        
        if status in TERMINAL_STATES:
            logging.info(f"任务 {task_id} 达到终态: {status}")
            return

        if sender == "Coordinator" or message_type == "Coordinator_Output":
            self._route_coordinator_output(task_id, agent_output, orig_env)
        elif sender == "SemgrepScanner":
            pass
        elif sender == "ReverseTracer":
            self._route_reverse_tracer_output(task_id, agent_output, orig_env)
        elif sender == "LogicAuditor":
            self._route_logic_auditor_output(task_id, agent_output, orig_env)
        elif sender == "RedValidator":
            self._route_red_validator_output(task_id, agent_output, orig_env)
        elif sender == "BlueValidator":
            self._route_blue_validator_output(task_id, agent_output, orig_env)
        elif sender == "ReportGenerator":
            self._route_report_generator_output(task_id, agent_output, orig_env)
        else:
            logging.warning(f"未知的发送者路由: {sender}")

    def _route_coordinator_output(self, task_id: str, agent_output: Dict[str, Any], orig_env: Dict[str, Any]):
        """处理包含裂变（Fan-out）逻辑的 Coordinator 输出。"""
        pass

    def _route_sinkhunter_output(self, task_id: str, agent_output: Dict[str, Any], sender: str):
        """SinkHunter 输出进入 ReverseTracer 进行追踪。"""
        # 检查是否有 sink_details（SinkHunter 返回的格式）
        sink_details = agent_output.get("sink_details")
        if sink_details:
            sink_key = sink_details.get("filepath", "") + str(sink_details.get("line_number", ""))
            if self.tracker: self.tracker.add_task()
            if self.tracker: self.tracker.update_kanban("suspicious", task_id + sink_key, "SINK", sink_details.get("filepath", "未知"))
            self.bus.write_message(
                message_type="TaskRequest",
                task_id=task_id + "_TRACE",
                sender=sender,
                recipient="ReverseTracer",
                payload={"action": "trace_call_chain", "sink_details": sink_details}
            )

    def _route_reverse_tracer_output(self, task_id: str, agent_output: Dict[str, Any], orig_env: Dict[str, Any]):
        """ReverseTracer 输出进入 RedValidator 进行攻击验证。"""
        # 支持 vuln_type 或 vuln_class 字段
        vuln_type = agent_output.get("vuln_type") or agent_output.get("vuln_class")
        if vuln_type:
            # 获取 entry_route，优先从 agent_output 获取，其次从 sink_details 获取
            entry_route = agent_output.get("entry_route")
            if not entry_route:
                sink_details = agent_output.get("sink_details", {})
                entry_route = sink_details.get("filepath", "未知")
            
            if self.tracker: self.tracker.add_task()
            if self.tracker:
                details = {
                    "call_chain": agent_output.get("call_chain"),
                    "suspicion_reason": agent_output.get("suspicion_reason"),
                    "vuln_type": agent_output.get("vuln_type") or agent_output.get("vuln_class"),
                    "entry_route": entry_route
                }
                self.tracker.update_kanban("red", task_id, vuln_type, entry_route, details=details)
            self.bus.write_message(
                message_type="VulnCandidate",
                task_id=task_id,
                sender="ReverseTracer",
                recipient="RedValidator",
                payload=agent_output
            )

    def _route_logic_auditor_output(self, task_id: str, agent_output: Dict[str, Any], orig_env: Dict[str, Any]):
        """LogicAuditor 输出进入 RedValidator 进行攻击验证。"""
        if "vuln_type" in agent_output:
            if self.tracker: self.tracker.add_task()
            if self.tracker: self.tracker.update_kanban("red", task_id, agent_output.get("vuln_type"), agent_output.get("entry_route", "未知"))
            self.bus.write_message(
                message_type="VulnCandidate",
                task_id=task_id,
                sender="LogicAuditor",
                recipient="RedValidator",
                payload=agent_output
            )
        else:
            if self.tracker: self.tracker.update_kanban("resolved", task_id, "LOGIC", "审计通过", status="DEFENDED")

    def _route_red_validator_output(self, task_id: str, agent_output: Dict[str, Any], orig_env: Dict[str, Any]):
        """RedValidator 输出进入 BlueValidator 进行防御验证。"""
        status = agent_output.get("status")
        if status == "EXPLOITABLE" or "attack_vector" in agent_output:
            payload = agent_output.copy()
            orig_payload = orig_env.get("payload", {})
            if "vuln_type" not in payload and "vuln_type" in orig_payload:
                payload["vuln_type"] = orig_payload.get("vuln_type")
            if "entry_route" not in payload and "entry_route" in orig_payload:
                payload["entry_route"] = orig_payload.get("entry_route")
            if "call_chain" not in payload and "call_chain" in orig_payload:
                payload["call_chain"] = orig_payload.get("call_chain")
            
            if self.tracker: self.tracker.add_task()
            if self.tracker:
                details = {
                    "attack_vector": payload.get("attack_vector"),
                    "poc_payload": payload.get("poc_payload"),
                    "max_impact": payload.get("max_impact"),
                    "call_chain": payload.get("call_chain"),
                    "suspicion_reason": payload.get("suspicion_reason"),
                    "vuln_type": payload.get("vuln_type"),
                    "entry_route": payload.get("entry_route")
                }
                self.tracker.update_kanban("blue", task_id, payload.get("vuln_type", "未知"), payload.get("entry_route", "未知"), details=details)
            self.bus.write_message(
                message_type="ExploitAttempt",
                task_id=task_id,
                sender="RedValidator",
                recipient="BlueValidator",
                payload=payload
            )
        else:
            if self.tracker: self.tracker.update_kanban("resolved", task_id, "RED-FAIL", "不可利用", status="DEFENDED")

    def _route_blue_validator_output(self, task_id: str, agent_output: Dict[str, Any], orig_env: Dict[str, Any]):
        """BlueValidator 输出进入 ReportGenerator 生成最终报告。"""
        status = agent_output.get("status")
        if status == "VULNERABLE" or "mitigation_advice" in agent_output:
            if self.tracker:
                details = {
                    "call_chain": agent_output.get("call_chain"),
                    "attack_vector": agent_output.get("attack_vector"),
                    "defense_analysis": agent_output.get("defense_analysis"),
                    "mitigation_advice": agent_output.get("mitigation_advice"),
                    "suspicion_reason": agent_output.get("suspicion_reason"),
                    "cwe": agent_output.get("cwe"),
                    "poc_payload": agent_output.get("poc_payload"),
                    "max_impact": agent_output.get("max_impact"),
                    "vulnerability": agent_output.get("vulnerability"),
                    "cwe_id": agent_output.get("cwe_id"),
                    "severity": agent_output.get("severity"),
                    "description": agent_output.get("description"),
                    "remediation": agent_output.get("remediation")
                }
                self.tracker.update_kanban(
                    "resolved", 
                    task_id, 
                    agent_output.get("vuln_type", "未知"), 
                    agent_output.get("entry_route", "未知"), 
                    status="CONFIRMED",
                    details=details
                )
            self.bus.write_message(
                message_type="ConfirmedVuln",
                task_id=task_id,
                sender="BlueValidator",
                recipient="ReportGenerator",
                payload=agent_output
            )
        else:
            if self.tracker: self.tracker.update_kanban("resolved", task_id, "BLUE-FAIL", "防御有效", status="DEFENDED")

    def _route_report_generator_output(self, task_id: str, agent_output: Dict[str, Any], orig_env: Dict[str, Any]):
        """ReportGenerator 是终点，负责生成最终审计报告。"""
        vuln_type = agent_output.get("vuln_type", "未知")
        entry_route = agent_output.get("entry_route", "未知")
        mitigation_advice = agent_output.get("mitigation_advice", "")
        
        logging.info(f"ReportGenerator 已完成任务 {task_id}: {vuln_type} @ {entry_route}")
        
        if mitigation_advice:
            logging.info(f"修复建议: {mitigation_advice}")
