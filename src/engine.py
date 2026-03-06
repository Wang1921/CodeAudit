import asyncio
import logging
import json
import os
from typing import Optional, Dict, Any
from src.a2a_bus import A2ABusManager
from src.agent import OpenCodeSubprocess
from src.state_router import StateRouter
from src.state_tracker import StateTracker
from src import prompts
from src.semgrep_scanner import SemgrepScanner

MAX_CONCURRENT_AGENTS = 20
MAX_AGENT_TIMEOUT = 1800

class AuditEngine:
    def __init__(self, target_source_dir: str):
        self.tracker = StateTracker(target_source_dir)
        self.bus = A2ABusManager(target_source_dir)
        self.router = StateRouter(self.bus, self.tracker)
        self.target_source_dir = target_source_dir
        self.semaphore = asyncio.Semaphore(MAX_CONCURRENT_AGENTS)
        self.dynamic_tracing_strategy = ""
    
    def _get_prompt_for_agent(self, agent_name: str, payload_json: str, context: Optional[Dict[str, Any]] = None) -> str:
        ctx: dict = context if context is not None else {}
        
        if agent_name == "Coordinator":
            return prompts.format_coordinator_prompt(payload_json)
        elif agent_name == "ReverseTracer":
            tracing_strategy = ctx.get('dynamic_tracing_strategy', '') or ''
            return prompts.format_reverse_tracer_prompt(payload_json, tracing_strategy)
        elif agent_name == "LogicAuditor":
            return prompts.format_logic_auditor_prompt(payload_json)
        elif agent_name == "RedValidator":
            return prompts.format_red_validator_prompt(payload_json)
        elif agent_name == "BlueValidator":
            return prompts.format_blue_validator_prompt(payload_json)
        elif agent_name == "ReportGenerator":
            return prompts.format_report_generator_prompt(payload_json)
        else:
            raise ValueError(f"未知的 Agent 类型: {agent_name}")

    def _fan_out_coordinator_output(self, task_id: str, coordinator_output: dict):
        routes = coordinator_output.get("routes", [])
        language = coordinator_output.get("language_stack", "java")
        self._language_stack = language
        
        self.dynamic_tracing_strategy = coordinator_output.get("tracing_strategy", "")
        
        logging.info(f"开始使用 Semgrep 扫描 {language} 项目...")
        scanner = SemgrepScanner(self.target_source_dir)
        scan_result = scanner.scan(language)
        
        sinks = scan_result.get("sinks", [])
        total = scan_result.get("total", 0)
        logging.info(f"Semgrep 扫描完成，发现 {total} 个潜在漏洞点")
        
        for i, sink in enumerate(sinks):
            self.tracker.add_task()
            sink_details = sink.get("sink_details", {})
            vuln_class = sink_details.get("vuln_class", "Unknown")
            filepath = sink_details.get("filepath", "Unknown")
            
            self.tracker.update_kanban(
                "suspicious", 
                f"{task_id}_SINK_{i}", 
                vuln_class,
                filepath
            )
            
            self.bus.write_message(
                message_type="TaskRequest",
                task_id=f"{task_id}_SINK_{i}_TRACE",
                sender="SemgrepScanner",
                recipient="ReverseTracer",
                payload={
                    "action": "trace_call_chain",
                    "sink_details": sink_details,
                    "tracing_strategy": self.dynamic_tracing_strategy
                }
            )
        
        for i, route in enumerate(routes):
            self.tracker.add_task()
            self.bus.write_message(
                message_type="TaskRequest",
                task_id=f"{task_id}_ROUTE_{i}",
                sender="Coordinator",
                recipient="LogicAuditor",
                payload={"action": "logic_audit", "route_details": route}
            )

    async def process_task(self, filepath: str):
        async with self.semaphore:
            try:
                env = self.bus.read_message(filepath)
                recipient = env["recipient"]
                payload_json = json.dumps(env["payload"], ensure_ascii=False)
                
                context = {}
                if "tracing_strategy" in env.get("payload", {}):
                    context["dynamic_tracing_strategy"] = env["payload"]["tracing_strategy"]
                elif hasattr(self, 'dynamic_tracing_strategy'):
                    context["dynamic_tracing_strategy"] = self.dynamic_tracing_strategy
                
                logging.info(f"Agent {recipient} 开始任务 {env['task_id']}")
                self.tracker.agent_start(env["task_id"], recipient, f"正在处理 {env['task_id']}")
                prompt = self._get_prompt_for_agent(recipient, payload_json, context)
                
                agent = OpenCodeSubprocess(self.target_source_dir, timeout=MAX_AGENT_TIMEOUT)
                try:
                    logging.info(f"正在执行 Agent {recipient}...")
                    result = await agent.execute(prompt)
                    logging.info(f"Agent {recipient} 执行完成。输出: {result}")
                    
                    tokens_used = result.pop('_tokens', 0)
                    if tokens_used > 0:
                        self.tracker.add_tokens(tokens_used)
                        logging.info(f"Agent {recipient} 消耗了 {tokens_used} tokens")
                    
                    message_type = env.get("message_type", "")
                    if recipient == "Coordinator":
                        self._fan_out_coordinator_output(env["task_id"], result)
                    
                    self.router.route(filepath, result)
                    self.bus.mark_completed(filepath, result)
                    self.tracker.agent_finish(env["task_id"])
                    logging.info(f"Agent {recipient} 已完成任务 {env['task_id']}")
                except Exception as e:
                    logging.error(f"Agent {recipient} 在任务 {env['task_id']} 上失败: {e}", exc_info=True)
                    self.bus.mark_failed(filepath)
                    self.tracker.agent_finish(env["task_id"])
                    self.bus.write_raw_failed(str(e), "执行或 JSON 解析错误")
            except Exception as e:
                logging.error(f"处理消息失败 {filepath}: {e}", exc_info=True)

    async def run(self):
        logging.info("正在启动代码审计引擎...")
        is_fresh_start = all(len(os.listdir(d)) == 0 for d in [
            self.bus.pending_dir, self.bus.processing_dir, self.bus.completed_dir, self.bus.help_req_dir
        ])
        
        if is_fresh_start:
            self.tracker.add_task()
            self.bus.write_message(
                message_type="TaskRequest",
                task_id="TASK-INIT-001",
                sender="System",
                recipient="Coordinator",
                payload={"action": "extract_routes"}
            )
            logging.info("已注入初始 Coordinator 任务。")

        async def update_tracker_loop():
            while True:
                self.tracker.update_agent_times()
                await asyncio.sleep(1)

        asyncio.create_task(update_tracker_loop())

        while True:
            tasks = self.bus.get_pending_tasks()
            if not tasks:
                await asyncio.sleep(1)
                continue

            for coro in tasks:
                asyncio.create_task(self.process_task(coro))
