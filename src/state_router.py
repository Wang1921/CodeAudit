import logging
from src.a2a_bus import A2ABusManager
from typing import Dict, Any

class StateRouter:
    def __init__(self, bus: A2ABusManager):
        self.bus = bus

    def route(self, completed_task: str, agent_output: Dict[str, Any]):
        """Route the output of an agent to the next hop."""
        orig_env = self.bus.read_message(completed_task)
        sender = orig_env["recipient"] # The agent that just finished
        task_id = orig_env["task_id"]

        # Terminal states check
        status = agent_output.get("status")
        if status in ["NOT_EXPLOITABLE", "DEFENDED"]:
            logging.info(f"Task {task_id} reached terminal state: {status}")
            return # Engine will move it to completed

        if sender == "Coordinator":
            # Fan-out to SinkHunters and LogicAuditors
            hunters = agent_output.get("hunters_to_dispatch", [])
            for hunter in hunters:
                cwe = hunter.get("cwe_profile")
                if cwe:
                    self.bus.write_message(
                        message_type="TaskRequest",
                        task_id=task_id,
                        sender="Coordinator",
                        recipient=f"SinkHunter_{cwe}",
                        payload={"action": "scan_sinks", "cwe_profile": cwe}
                    )
            
            routes = agent_output.get("routes", [])
            for route in routes:
                self.bus.write_message(
                    message_type="TaskRequest",
                    task_id=task_id,
                    sender="Coordinator",
                    recipient="LogicAuditor",
                    payload={"action": "logic_audit", "route_details": route}
                )

        elif sender.startswith("SinkHunter"):
            # Output from SinkHunter goes to ReverseTracer
            sinks = agent_output.get("found_sinks", [])
            for sink in sinks:
                self.bus.write_message(
                    message_type="TaskRequest",
                    task_id=task_id,
                    sender=sender,
                    recipient="ReverseTracer",
                    payload={"action": "trace_call_chain", "sink_details": sink}
                )

        elif sender == "ReverseTracer":
            if "vuln_type" in agent_output:
                self.bus.write_message(
                    message_type="VulnCandidate",
                    task_id=task_id,
                    sender="ReverseTracer",
                    recipient="RedValidator",
                    payload=agent_output
                )

        elif sender == "LogicAuditor":
            if "vuln_type" in agent_output:
                self.bus.write_message(
                    message_type="VulnCandidate",
                    task_id=task_id,
                    sender="LogicAuditor",
                    recipient="RedValidator",
                    payload=agent_output
                )

        elif sender == "RedValidator":
            if status == "EXPLOITABLE" or "attack_vector" in agent_output:
                # Merge original payload for BlueValidator context if needed
                payload = agent_output.copy()
                payload.update({
                    "vuln_type": orig_env["payload"].get("vuln_type"),
                    "entry_route": orig_env["payload"].get("entry_route")
                })
                self.bus.write_message(
                    message_type="ExploitAttempt",
                    task_id=task_id,
                    sender="RedValidator",
                    recipient="BlueValidator",
                    payload=payload
                )

        elif sender == "BlueValidator":
            if status == "VULNERABLE" or "mitigation_advice" in agent_output:
                self.bus.write_message(
                    message_type="ConfirmedVuln",
                    task_id=task_id,
                    sender="BlueValidator",
                    recipient="ReportGenerator",
                    payload=agent_output
                )
        else:
            logging.warning(f"Unknown routing from sender: {sender}")
