import logging
from src.a2a_bus import A2ABusManager
from typing import Dict, Any

NEXT_HOP_ROUTING = {
    "System": {
        "TaskRequest": "Coordinator"
    },
    "Coordinator": {
        "Coordinator_Output": "Fan-out (SinkHunter集群 + LogicAuditor)"
    },
    "SinkHunter": {
        "TaskRequest": "ReverseTracer"
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
        elif sender.startswith("SinkHunter"):
            self._route_sinkhunter_output(task_id, agent_output, sender)
        elif sender == "ReverseTracer":
            self._route_reverse_tracer_output(task_id, agent_output, orig_env)
        elif sender == "LogicAuditor":
            self._route_logic_auditor_output(task_id, agent_output, orig_env)
        elif sender == "RedValidator":
            self._route_red_validator_output(task_id, agent_output, orig_env)
        elif sender == "BlueValidator":
            self._route_blue_validator_output(task_id, agent_output, orig_env)
        else:
            logging.warning(f"未知的发送者路由: {sender}")

    def _route_coordinator_output(self, task_id: str, agent_output: Dict[str, Any], orig_env: Dict[str, Any]):
        """处理包含裂变（Fan-out）逻辑的 Coordinator 输出。"""
        pass

    def _route_sinkhunter_output(self, task_id: str, agent_output: Dict[str, Any], sender: str):
        """SinkHunter 输出进入 ReverseTracer 进行追踪。"""
        sinks = agent_output.get("found_sinks", [])
        for sink in sinks:
            if self.tracker: self.tracker.add_task()
            if self.tracker: self.tracker.update_kanban("suspicious", task_id + sink.get("route", ""), "SINK", sink.get("route", "未知触点"))
            self.bus.write_message(
                message_type="TaskRequest",
                task_id=task_id + "_TRACE",
                sender=sender,
                recipient="ReverseTracer",
                payload={"action": "trace_call_chain", "sink_details": sink}
            )

    def _route_reverse_tracer_output(self, task_id: str, agent_output: Dict[str, Any], orig_env: Dict[str, Any]):
        """ReverseTracer 输出进入 RedValidator 进行攻击验证。"""
        if "vuln_type" in agent_output:
            if self.tracker: self.tracker.add_task()
            if self.tracker: self.tracker.update_kanban("red", task_id, agent_output.get("vuln_type"), agent_output.get("entry_route", "未知"))
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
            if self.tracker: self.tracker.update_kanban("blue", task_id, payload.get("vuln_type", "未知"), payload.get("entry_route", "未知"))
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
            if self.tracker: self.tracker.update_kanban("resolved", task_id, agent_output.get("vuln_type", "未知"), agent_output.get("entry_route", "未知"), status="CONFIRMED")
            self.bus.write_message(
                message_type="ConfirmedVuln",
                task_id=task_id,
                sender="BlueValidator",
                recipient="ReportGenerator",
                payload=agent_output
            )
        else:
            if self.tracker: self.tracker.update_kanban("resolved", task_id, "BLUE-FAIL", "防御有效", status="DEFENDED")
