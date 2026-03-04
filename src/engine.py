import asyncio
import logging
import json
import os
from src.a2a_bus import A2ABusManager
from src.agent import OpenCodeSubprocess
from src.state_router import StateRouter
from src import prompts

MAX_CONCURRENT_AGENTS = 20
MAX_AGENT_TIMEOUT = 1800

class AuditEngine:
    def __init__(self, target_source_dir: str):
        self.bus = A2ABusManager(target_source_dir)
        self.router = StateRouter(self.bus)
        self.target_source_dir = target_source_dir
        self.semaphore = asyncio.Semaphore(MAX_CONCURRENT_AGENTS)
        self.hunter_registry = prompts.load_hunter_registry()
        self.language_hunters = {}
        self.dynamic_tracing_strategy = ""

    def _get_language_hunters(self, language: str) -> dict:
        """Load and cache hunters for a specific language."""
        if language not in self.language_hunters:
            self.language_hunters[language] = prompts.get_hunter_templates_for_language(language)
        return self.language_hunters[language]

    def _get_prompt_for_agent(self, agent_name: str, payload_json: str, context: dict = None) -> str:
        """Get the prompt for a specific agent, using YAML templates if available."""
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
        elif agent_name.startswith("SinkHunter"):
            hunter_name = agent_name.replace("SinkHunter_", "")
            hunters = self._get_language_hunters(self._get_current_language())
            if hunter_name in hunters:
                return prompts.format_hunter_prompt(
                    hunters[hunter_name]['template'],
                    hunter_name,
                    payload_json
                )
            return prompts.SINK_HUNTER_PROMPT.format(hunter_name=hunter_name, payload_json=payload_json)
        else:
            raise ValueError(f"Unknown agent type: {agent_name}")

    def _get_current_language(self) -> str:
        """Get the current language stack from Coordinator output."""
        return getattr(self, '_language_stack', 'java')

    def _get_tools_for_agent(self, agent_name: str) -> str:
        """Determine tools based on agent type for least privilege principle."""
        if agent_name in ["Coordinator"]:
            return "bash,read,glob,grep"
        elif agent_name in ["ReverseTracer", "LogicAuditor"]:
            return "bash,read,glob,grep"
        elif agent_name.startswith("SinkHunter"):
            return "bash,read,glob,grep"
        elif agent_name in ["RedValidator", "BlueValidator"]:
            return "bash,read,glob,grep"
        return "bash,read,glob,grep"

    def _fan_out_coordinator_output(self, task_id: str, coordinator_output: dict):
        """Perform fan-out from Coordinator output with mandatory overrides."""
        routes = coordinator_output.get("routes", [])
        language = coordinator_output.get("language_stack", "java")
        self._language_stack = language
        self.dynamic_tracing_strategy = coordinator_output.get("tracing_strategy", "")
        
        recommended_hunters = coordinator_output.get("hunters_to_dispatch", [])
        
        language_hunters = self._get_language_hunters(language)
        recommended_hunter_names = set()
        
        for hunter in recommended_hunters:
            cwe = hunter.get("cwe_profile", "")
            for name, info in language_hunters.items():
                if cwe and cwe in info.get('cwe_profile', ''):
                    recommended_hunter_names.add(name)
        
        universal_hunters = self.hunter_registry.get('universal_hunters', [])
        for uh in universal_hunters:
            hunter_name = uh.get('name')
            template_path = uh.get('template_file')
            if template_path:
                try:
                    template = prompts.load_yaml_template(template_path)
                    self.language_hunters[hunter_name] = {
                        'template': template,
                        'cwe_profile': uh.get('cwe_profile', ''),
                        'description': uh.get('description', '')
                    }
                except Exception as e:
                    logging.warning(f"Failed to load universal hunter {hunter_name}: {e}")
        
        for hunter_name in recommended_hunter_names:
            self.bus.write_message(
                message_type="TaskRequest",
                task_id=f"{task_id}_HUNTER_{hunter_name}",
                sender="Coordinator",
                recipient=f"SinkHunter_{hunter_name}",
                payload={"action": "scan_sinks", "cwe_profile": language_hunters.get(hunter_name, {}).get('cwe_profile', '')}
            )
        
        for i, route in enumerate(routes):
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
                
                logging.info(f"Agent {recipient} starting task {env['task_id']}")
                prompt = self._get_prompt_for_agent(recipient, payload_json, context)
                
                tools = self._get_tools_for_agent(recipient)
                
                agent = OpenCodeSubprocess(self.target_source_dir, timeout=MAX_AGENT_TIMEOUT)
                try:
                    logging.info(f"Executing Agent {recipient}...")
                    result = await agent.execute(prompt, tools)
                    logging.info(f"Agent {recipient} execution finished. Output: {result}")
                    
                    message_type = env.get("message_type", "")
                    if message_type == "Coordinator_Output" or (env["sender"] == "Coordinator" and recipient == "Coordinator"):
                        self._fan_out_coordinator_output(env["task_id"], result)
                    
                    self.router.route(filepath, result)
                    self.bus.mark_completed(filepath)
                    logging.info(f"Agent {recipient} completed task {env['task_id']}")
                except Exception as e:
                    logging.error(f"Agent {recipient} failed on task {env['task_id']}: {e}", exc_info=True)
                    self.bus.mark_failed(filepath)
                    self.bus.write_raw_failed(str(e), "Execution or JSON parse error")
            except Exception as e:
                logging.error(f"Failed to process message {filepath}: {e}", exc_info=True)

    async def run(self):
        logging.info("Starting Audit Engine...")
        is_fresh_start = all(len(os.listdir(d)) == 0 for d in [
            self.bus.pending_dir, self.bus.processing_dir, self.bus.completed_dir, self.bus.help_req_dir
        ])
        
        if is_fresh_start:
            self.bus.write_message(
                message_type="TaskRequest",
                task_id="TASK-INIT-001",
                sender="System",
                recipient="Coordinator",
                payload={"action": "extract_routes"}
            )
            logging.info("Injected initial Coordinator task.")

        while True:
            tasks = self.bus.get_pending_tasks()
            if not tasks:
                await asyncio.sleep(1)
                continue

            for coro in tasks:
                asyncio.create_task(self.process_task(coro))
