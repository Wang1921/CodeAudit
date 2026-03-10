import asyncio
import logging
import json
import os
from pathlib import Path
from typing import Optional, Dict, Any
from src.a2a_bus import A2ABusManager
from src.agent import OpenCodeAgent
from src.state_router import StateRouter
from src.state_tracker import StateTracker
from src import prompts
from src.semgrep_scanner import SemgrepScanner
from src.server_manager import OpenCodeServerManager

MAX_CONCURRENT_AGENTS = 20
MAX_AGENT_TIMEOUT = 1800

class AuditEngine:
    def __init__(self, target_source_dir: str, semgrep_rules: str = None):
        self.tracker = StateTracker(target_source_dir)
        self.bus = A2ABusManager(target_source_dir)
        self.router = StateRouter(self.bus, self.tracker)
        self.target_source_dir = target_source_dir
        self.semgrep_rules = semgrep_rules
        self.semaphore = asyncio.Semaphore(MAX_CONCURRENT_AGENTS)
        self.dynamic_tracing_strategy = ""
        # 全局服务路由字典：service_name -> service_root_dir
        self.service_route_map: dict = {}
        # 沙盒池管理器
        self.server_manager = OpenCodeServerManager(max_active_servers=5)

    def _get_service_dir(self, filepath: str) -> str:
        """根据文件路径，推断其所属的微服务根目录。
        优先从 Coordinator 建立的 service_route_map 中查找，
        回退到启发式逻辑：寻找包含 pom.xml / go.mod / package.json 的最近父目录。
        """
        # 优先使用 Coordinator 建立的服务映射表
        if self.service_route_map:
            for service_name, service_dir in self.service_route_map.items():
                if filepath.startswith(service_name + "/") or filepath.startswith(service_name + os.sep):
                    logging.info(f"[ServiceDir] '{filepath}' 归属微服务 '{service_name}' -> {service_dir}")
                    return service_dir

        # 启发式回退：逐级向上查找构建文件
        parts = filepath.replace("\\", "/").split("/")
        build_markers = ("pom.xml", "go.mod", "package.json", "build.gradle")
        for depth in range(1, min(len(parts), 4)):
            candidate = os.path.join(self.target_source_dir, *parts[:depth])
            if os.path.isdir(candidate):
                for marker in build_markers:
                    if os.path.exists(os.path.join(candidate, marker)):
                        logging.info(f"[ServiceDir] '{filepath}' 启发式识别微服务目录: {candidate}")
                        return candidate

        logging.info(f"[ServiceDir] '{filepath}' 未识别到独立微服务目录，使用根目录")
        return self.target_source_dir
    
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

        # 构建全局服务路由字典，供后续 _get_service_dir() 查表
        self.service_route_map = {}
        for route in routes:
            svc = route.get("owning_service", "")
            if svc and svc not in self.service_route_map:
                svc_dir = os.path.join(self.target_source_dir, svc)
                if os.path.isdir(svc_dir):
                    self.service_route_map[svc] = svc_dir
        rpc_providers = coordinator_output.get("rpc_providers", [])
        for provider in rpc_providers:
            svc = provider.get("service_name", "")
            if svc and svc not in self.service_route_map:
                svc_dir = os.path.join(self.target_source_dir, svc)
                if os.path.isdir(svc_dir):
                    self.service_route_map[svc] = svc_dir
        if self.service_route_map:
            logging.info(f"[ServiceRegistry] 已注册 {len(self.service_route_map)} 个微服务: {list(self.service_route_map.keys())}")
        
        logging.info(f"开始使用 Semgrep 扫描 {language} 项目...")
        scanner = SemgrepScanner(self.target_source_dir, rules_path=self.semgrep_rules)
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

                # 拦截跨微服务异地重拉起请求
                if recipient == "Orchestrator" and env.get("message_type") == "CrossServiceTraceRequest":
                    await self._handle_cross_service_reinstantiation(env, filepath)
                    return

                context = {}
                if "tracing_strategy" in env.get("payload", {}):
                    context["dynamic_tracing_strategy"] = env["payload"]["tracing_strategy"]
                elif hasattr(self, 'dynamic_tracing_strategy'):
                    context["dynamic_tracing_strategy"] = self.dynamic_tracing_strategy

                logging.info(f"Agent {recipient} 开始任务 {env['task_id']}")
                self.tracker.agent_start(env["task_id"], recipient, f"正在处理 {env['task_id']}")
                prompt = self._get_prompt_for_agent(recipient, payload_json, context)

                # 动态推断目录与分配工具权限
                if recipient == "Coordinator":
                    target_cwd = self.target_source_dir  # 上帝视角：锁定根目录
                    allowed_tools = "codesearch,glob,grep,read" # 绝对不给 lsp
                else:
                    sink_file = env.get("payload", {}).get("sink_details", {}).get("filepath", "")
                    target_cwd = self._get_service_dir(sink_file) # 局部空投：进入微服务子目录
                    allowed_tools = "lsp,read,codesearch" # 开启重型武器 lsp

                # 通过 Server Pool 获取端口
                port = await self.server_manager.get_or_start_server(target_cwd)

                # 使用 HTTP Agent 执行
                agent = OpenCodeAgent(port=port, timeout=MAX_AGENT_TIMEOUT)
                result = await agent.execute(prompt, allowed_tools=allowed_tools)

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
                logging.error(f"处理消息失败 {filepath}: {e}", exc_info=True)

    async def _handle_cross_service_reinstantiation(self, env: dict, filepath: str):
        """接管跨界请求：在所有微服务沙盒中并发拉起接力 ReverseTracer。"""
        payload = env["payload"]
        task_id = env["task_id"]
        protocol = payload.get("protocol", "HTTP")
        target_id = payload.get("target_identifier", "unknown")

        logging.info(f"引擎接管跨界请求: 全局搜寻 {protocol} -> '{target_id}' 的调用方")

        # 微服务发现：优先使用已注册的服务目录，否则枚举根目录一级子目录
        if self.service_route_map:
            service_dirs = [Path(d) for d in self.service_route_map.values()]
        else:
            root_path = Path(self.target_source_dir)
            service_dirs = [d for d in root_path.iterdir() if d.is_dir() and not d.name.startswith('.')]

        if not service_dirs:
            logging.warning("未发现其他微服务目录，跨界追踪终止。")
            self.bus.mark_failed(filepath)
            return

        cross_tracing_strategy = (
            f"【最高优先级跨界任务】: 你的前序特工在另一个微服务发现了漏洞，"
            f"你需要接力追踪！请全局搜索当前代码库，找到所有向 {protocol} 目标 `{target_id}` "
            f"发起请求或发送消息的代码点（如 RestTemplate.postForObject('{target_id}') 或 kafkaTemplate.send('{target_id}')）。"
            f"以这些发送点为 Sink 坐标，继续向上逆向追踪到当前微服务的外部可控 API 入口！\n"
            f"【历史调用链参考】: {json.dumps(payload.get('historical_chain', []), ensure_ascii=False)}"
        )

        relay_payload = {
            "action": "trace_call_chain",
            "sink_details": {
                "vuln_class": payload.get("vuln_type", "CROSS_SERVICE_VULN"),
                "filepath": "Cross-Boundary Discovery",
                "line_number": 0,
                "taint_variable": payload.get("taint_variable", "payload")
            }
        }
        prompt = self._get_prompt_for_agent(
            "ReverseTracer",
            json.dumps(relay_payload, ensure_ascii=False),
            {"dynamic_tracing_strategy": cross_tracing_strategy}
        )

        for service_dir in service_dirs:
            asyncio.create_task(
                self._run_relay_agent(str(service_dir), prompt, task_id, service_dir.name, payload.get("vuln_type"))
            )

        self.bus.mark_completed(filepath, {"status": "DISPATCHED_GLOBALLY"})

    async def _run_relay_agent(self, service_dir: str, prompt: str, base_task_id: str, service_name: str, vuln_type: str):
        """在指定微服务目录异地执行接力 ReverseTracer，将贯通结果注入红蓝流水线。"""
        logging.info(f"在微服务 [{service_name}] 异地拉起溯源特工...")
        try:
            # 通过 Server Pool 获取端口
            port = await self.server_manager.get_or_start_server(service_dir)
            # 使用 HTTP Agent 执行
            agent = OpenCodeAgent(port=port, timeout=MAX_AGENT_TIMEOUT)
            result = await agent.execute(prompt, allowed_tools="lsp,read,codesearch")
            tokens_used = result.pop('_tokens', 0)
            if tokens_used > 0:
                self.tracker.add_tokens(tokens_used)

            if result.get("status") != "NOT_EXPLOITABLE":
                logging.info(f"微服务 [{service_name}] 成功接力并贯通外网入口！")
                self.tracker.add_task()
                self.bus.write_message(
                    message_type="VulnCandidate",
                    task_id=f"{base_task_id}_HIT_{service_name}",
                    sender="ReverseTracer",
                    recipient="RedValidator",
                    payload=result
                )
            else:
                logging.debug(f"微服务 [{service_name}] 中未发现调用链路。")
        except Exception as e:
            logging.error(f"微服务 [{service_name}] 接力追踪异常: {e}")

    async def run(self):
        try:
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
        finally:
            await self.server_manager.shutdown_all()
