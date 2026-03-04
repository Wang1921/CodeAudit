import asyncio
import logging
import json
import os
from src.a2a_bus import A2ABusManager
from src.agent import OpenCodeSubprocess
from src.state_router import StateRouter
from src import prompts

MAX_CONCURRENT_AGENTS = 20

class AuditEngine:
    def __init__(self, target_source_dir: str):
        self.bus = A2ABusManager(target_source_dir)
        self.router = StateRouter(self.bus)
        self.target_source_dir = target_source_dir
        self.semaphore = asyncio.Semaphore(MAX_CONCURRENT_AGENTS)

    def _get_prompt_for_agent(self, agent_name: str, payload_json: str) -> str:
        if agent_name == "Coordinator":
            return prompts.COORDINATOR_PROMPT.format(payload_json=payload_json)
        elif agent_name.startswith("SinkHunter"):
            return prompts.SINK_HUNTER_PROMPT.format(hunter_name=agent_name, payload_json=payload_json)
        elif agent_name == "ReverseTracer":
            return prompts.REVERSE_TRACER_PROMPT.format(payload_json=payload_json)
        elif agent_name == "LogicAuditor":
            return prompts.LOGIC_AUDITOR_PROMPT.format(payload_json=payload_json)
        elif agent_name == "RedValidator":
            return prompts.RED_VALIDATOR_PROMPT.format(payload_json=payload_json)
        elif agent_name == "BlueValidator":
            return prompts.BLUE_VALIDATOR_PROMPT.format(payload_json=payload_json)
        else:
            raise ValueError(f"Unknown agent type: {agent_name}")

    async def process_task(self, filepath: str):
        async with self.semaphore:
            try:
                env = self.bus.read_message(filepath)
                recipient = env["recipient"]
                payload_json = json.dumps(env["payload"], ensure_ascii=False)
                
                logging.info(f"Agent {recipient} starting task {env['task_id']}")
                prompt = self._get_prompt_for_agent(recipient, payload_json)
                
                # Determine tools based on agent type
                tools = None
                if recipient in ["ReverseTracer", "Coordinator", "LogicAuditor"]:
                    tools = "bash,read,glob,grep" # Give them read access
                
                agent = OpenCodeSubprocess(self.target_source_dir)
                try:
                    logging.info(f"Executing Agent {recipient}...")
                    result = await agent.execute(prompt, tools)
                    logging.info(f"Agent {recipient} execution finished. Output: {result}")
                    # Route result
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

            # Fan out tasks
            coroutines = [self.process_task(t) for t in tasks]
            # We don't await them directly here to avoid blocking the loop,
            # Instead, we create background tasks.
            for coro in coroutines:
                asyncio.create_task(coro)
