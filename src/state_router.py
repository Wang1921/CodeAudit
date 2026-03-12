import logging
import json
import os
from datetime import datetime
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
        "VulnCandidate": "RedValidator",
        "CrossServiceTraceRequest": "Orchestrator"
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
    
    def _extract_json_from_str(self, text):
        """从字符串中提取 JSON，按优先级尝试：标准 JSON → Markdown 代码块 → 文本中的 JSON 片段"""
        import re
        
        # 1. 直接尝试解析标准 JSON
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        
        # 2. 提取 Markdown 代码块（支持 ```json 和 ```）
        match = re.search(r'```(?:json)?\s*\n(.*?)\n```', text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                pass
        
        # 3. 从文本中提取 JSON 片段（第一个 {} 或 []）
        # 简化版：只支持一级嵌套
        json_pattern = r'(\{[^{}]*(?:\{[^{}]*\})*[^{}]*\})|(\[[^\[\]]*(?:\[[^\[\]]*\])*[^\[\]]*\])'
        match = re.search(json_pattern, text, re.DOTALL)
        if match:
            json_str = match.group(1) or match.group(2)
            try:
                return json.loads(json_str)
            except json.JSONDecodeError:
                pass
        
        # 所有尝试失败，返回空字典
        logging.warning(f"JSON 解析失败，返回空字典。输入预览: {text[:200]}...")
        return {}
    
    def _parse_json_output(self, output):
        """解析可能是 Markdown 格式或普通文本中包含 JSON 的输出"""
        if isinstance(output, dict):
            if "response" in output:
                return self._extract_json_from_str(str(output["response"]))
            return output
        return self._extract_json_from_str(str(output))

    def route(self, completed_task: str, agent_output: Dict[str, Any]):
        """将 Agent 的输出路由到下一跳。"""
        orig_env = self.bus.read_message(completed_task)
        sender = orig_env["recipient"]
        task_id = orig_env["task_id"]
        message_type = orig_env.get("message_type", "TaskRequest")
  
        # 首先解析 agent_output 中的 response 字段（如果有 Markdown 包装）
        parsed_output = self._parse_json_output(agent_output)
        status = parsed_output.get("status")
        
        logging.info(f"[路由] {sender} -> ? | task_id={task_id} | parsed keys: {list(parsed_output.keys())}")
        
        if status in TERMINAL_STATES:
            logging.info(f"任务 {task_id} 达到终态: {status}")
            return
  
        # 拦截跨界追踪求救信号
        if sender == "ReverseTracer" and parsed_output.get("action") == "cross_service_trace":
            self._route_cross_service_request(task_id, parsed_output, orig_env)
            return
  
        if sender == "Coordinator" or message_type == "Coordinator_Output":
            self._route_coordinator_output(task_id, agent_output, orig_env)
        elif sender == "SemgrepScanner":
            pass
        elif sender == "ReverseTracer":
            self._route_reverse_tracer_output(task_id, parsed_output, orig_env)
        elif sender == "LogicAuditor":
            self._route_logic_auditor_output(task_id, parsed_output, orig_env)
        elif sender == "RedValidator":
            self._route_red_validator_output(task_id, agent_output, orig_env)
        elif sender == "BlueValidator":
            self._route_blue_validator_output(task_id, agent_output, orig_env)
        elif sender == "ReportGenerator":
            self._route_report_generator_output(task_id, agent_output, orig_env)
        else:
            logging.warning(f"未知的发送者路由: {sender}")

    def _route_cross_service_request(self, task_id: str, agent_output: Dict[str, Any], orig_env: Dict[str, Any]):
        """将跨微服务追踪请求路由给 Orchestrator（引擎主循环特殊处理）。"""
        # agent_output 已经在 route() 中解析过了
        target = agent_output.get("target_identifier", "unknown")
        logging.info(f"触发跨微服务追踪求救信号: {task_id} -> 目标: {target}")

        if self.tracker:
            self.tracker.add_task()
            self.tracker.update_kanban("suspicious", f"{task_id}_CROSS", "CROSS_SERVICE", target)

        self.bus.write_message(
            message_type="CrossServiceTraceRequest",
            task_id=f"{task_id}_CROSS",
            sender="ReverseTracer",
            recipient="Orchestrator",
            payload=agent_output,
            priority="high"
        )

    def _route_coordinator_output(self, task_id: str, agent_output: Dict[str, Any], orig_env: Dict[str, Any]):
        """处理包含裂变（Fan-out）逻辑的 Coordinator 输出。"""
        pass

    def _route_reverse_tracer_output(self, task_id: str, agent_output: Dict[str, Any], orig_env: Dict[str, Any]):
        """ReverseTracer 输出进入 RedValidator 进行攻击验证。"""
        logging.info(f"[路由] ReverseTracer -> RedValidator | vuln_type={agent_output.get('vuln_type')}")
        # 支持 vuln_type 或 vuln_class 字段
        # 注意: agent_output 已经在 route() 方法中解析过了
        vuln_type = agent_output.get("vuln_type") or agent_output.get("vuln_class")
        if vuln_type:
            # 获取 entry_route，优先从 agent_output 获取，其次从 sink_details。
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
        logging.info(f"[路由] LogicAuditor -> ? | vuln_type={agent_output.get('vuln_type')} | keys={list(agent_output.keys())}")
        # 注意: agent_output 已经在 route() 方法中解析过了
        
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
        # 解析可能包含 Markdown 的 JSON 输出
        parsed_output = self._parse_json_output(agent_output)
        status = parsed_output.get("status")
        logging.info(f"[路由] RedValidator -> ? | status={status} | attack_vector={'attack_vector' in parsed_output}")
        if status == "EXPLOITABLE" or "attack_vector" in parsed_output:
            payload = parsed_output.copy()
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
        # 解析可能包含 Markdown 的 JSON 输出
        parsed_output = self._parse_json_output(agent_output)
        status = parsed_output.get("status")
        if status == "VULNERABLE" or "mitigation_advice" in parsed_output:
            if self.tracker:
                details = {
                    "call_chain": parsed_output.get("call_chain"),
                    "attack_vector": parsed_output.get("attack_vector"),
                    "defense_analysis": parsed_output.get("defense_analysis"),
                    "mitigation_advice": parsed_output.get("mitigation_advice"),
                    "suspicion_reason": parsed_output.get("suspicion_reason"),
                    "cwe": parsed_output.get("cwe"),
                    "poc_payload": parsed_output.get("poc_payload"),
                    "max_impact": parsed_output.get("max_impact"),
                    "vulnerability": parsed_output.get("vulnerability"),
                    "cwe_id": parsed_output.get("cwe_id"),
                    "severity": parsed_output.get("severity"),
                    "description": parsed_output.get("description"),
                    "remediation": parsed_output.get("remediation")
                }
                self.tracker.update_kanban(
                    "resolved", 
                    task_id, 
                    parsed_output.get("vuln_type", "未知"), 
                    parsed_output.get("entry_route", "未知"), 
                    status="CONFIRMED",
                    details=details
                )
            self.bus.write_message(
                message_type="ConfirmedVuln",
                task_id=task_id,
                sender="BlueValidator",
                recipient="ReportGenerator",
                payload=parsed_output
            )
        else:
            if self.tracker: self.tracker.update_kanban("resolved", task_id, "BLUE-FAIL", "防御有效", status="DEFENDED")

    def _route_report_generator_output(self, task_id: str, agent_output: Dict[str, Any], orig_env: Dict[str, Any]):
        """ReportGenerator 是终点，负责生成最终审计报告。"""
        # 解析可能包含 Markdown 的 JSON 输出
        parsed_output = self._parse_json_output(agent_output)
        
        vuln_type = parsed_output.get("vuln_type", "未知")
        entry_route = parsed_output.get("entry_route", "未知")
        mitigation_advice = parsed_output.get("mitigation_advice", "")
        
        logging.info(f"ReportGenerator 已完成任务 {task_id}: {vuln_type} @ {entry_route}")
        
        if mitigation_advice:
            logging.info(f"修复建议: {mitigation_advice}")
        
        self._save_vulnerability_report(task_id, parsed_output)
    
    def _save_vulnerability_report(self, task_id: str, agent_output: Dict[str, Any]):
        """将漏洞报告保存到磁盘。"""
        try:
            output_dir = "reports"
            os.makedirs(output_dir, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"vulnerability_{task_id}_{timestamp}.json"
            filepath = os.path.join(output_dir, filename)
            
            report = {
                "task_id": task_id,
                "timestamp": datetime.now().isoformat(),
                "vuln_type": agent_output.get("vuln_type", "未知"),
                "entry_route": agent_output.get("entry_route", "未知"),
                "mitigation_advice": agent_output.get("mitigation_advice", ""),
                "description": agent_output.get("description", ""),
                "severity": agent_output.get("severity", ""),
                "cwe_id": agent_output.get("cwe_id", ""),
                "poc_payload": agent_output.get("poc_payload", ""),
                "max_impact": agent_output.get("max_impact", ""),
                "defense_analysis": agent_output.get("defense_analysis", ""),
                "remediation": agent_output.get("remediation", ""),
                "attack_vector": agent_output.get("attack_vector", ""),
                "call_chain": agent_output.get("call_chain", []),
                "suspicion_reason": agent_output.get("suspicion_reason", ""),
                "cwe": agent_output.get("cwe", ""),
                "vulnerability": agent_output.get("vulnerability", "")
            }
            
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
            
            logging.info(f"漏洞报告已保存到: {filepath}")
        except Exception as e:
            logging.error(f"保存漏洞报告失败: {e}")