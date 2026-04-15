import asyncio
import logging
import json
import os
from pathlib import Path
from typing import Optional, Dict, Tuple
from src.a2a_bus import A2ABusManager
from src.agent import OpenCodeAgent
from src.state_router import StateRouter
from src.state_tracker import StateTracker
from src import prompts
from src.semgrep_scanner import SemgrepScanner
from src.server_manager import OpenCodeServerManager

MAX_CONCURRENT_AGENTS = 20
MAX_AGENT_TIMEOUT = 3600

class AuditEngine:
    def __init__(self, target_source_dir: str, semgrep_rules: Optional[str] = None):
        self.tracker = StateTracker(target_source_dir)
        self.bus = A2ABusManager(target_source_dir)
        self.router = StateRouter(self.bus, self.tracker)
        self.target_source_dir = target_source_dir
        self.semgrep_rules = semgrep_rules
        self.semaphore = asyncio.Semaphore(MAX_CONCURRENT_AGENTS)
        # 全局服务路由字典：service_name -> service_root_dir
        self.service_route_map: dict = {}
        # 沙盒池管理器
        self.server_manager = OpenCodeServerManager(max_active_servers=5)
        # 跨微服务追踪结果缓存：(protocol, target_identifier) -> Future[Dict[service_name, parsed_result|None]]
        # 使用 Future 实现 in-flight coalescing：并发同 key 请求共享同一次计算
        self._cross_service_cache: Dict[Tuple[str, str], asyncio.Future] = {}
        self._cross_service_cache_lock = asyncio.Lock()

    def _get_service_dir(self, filepath: str) -> str:
        """根据文件路径，推断其所属的微服务根目录。
        优先从已发现的服务映射表中查找，
        回退到启发式逻辑：寻找包含 pom.xml / go.mod / package.json 的最近父目录。
        """
        # 优先使用已发现的服务映射表
        if self.service_route_map:
            for service_name, service_dir in self.service_route_map.items():
                if service_dir in filepath:
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
    
    def _get_prompt_for_agent(self, agent_name: str, payload_json: str) -> str:
        if agent_name == "ReverseTracer":
            return prompts.format_reverse_tracer_prompt(payload_json)
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

    def _discover_microservices(self) -> dict:
        """扫描目标目录的第一层子目录，发现微服务"""
        service_map = {}
        root_path = Path(self.target_source_dir)
        
        if not root_path.exists():
            logging.warning(f"目标目录不存在: {self.target_source_dir}")
            return service_map
        
        for entry in root_path.iterdir():
            if entry.is_dir() and not entry.name.startswith('.'):
                service_map[entry.name] = str(entry)
        
        if service_map:
            logging.info(f"[ServiceDiscovery] 发现 {len(service_map)} 个微服务: {list(service_map.keys())}")
        else:
            logging.info(f"[ServiceDiscovery] 未发现子目录，使用根目录作为唯一服务")
            service_map["main"] = self.target_source_dir
        
        return service_map

    def _dispatch_scan_results(self, task_id: str, scan_result: dict):
        """分发 Semgrep 扫描结果到各个 Agent"""
        
        # 处理路由结果
        routes = scan_result.get("routes", [])
        for i, route in enumerate(routes):
            self.tracker.add_task()
            self.bus.write_message(
                message_type="TaskRequest",
                task_id=f"{task_id}_ROUTE_{i}",
                sender="SemgrepScanner",
                recipient="LogicAuditor",
                payload={"action": "logic_audit", "route_details": route}
            )
        
        # 处理漏洞点结果
        sinks = scan_result.get("sinks", [])
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
                    "sink_details": sink_details
                }
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

                logging.info(f"Agent {recipient} 开始任务 {env['task_id']}")
                self.tracker.agent_start(env["task_id"], recipient, f"正在处理 {env['task_id']}")
                prompt = self._get_prompt_for_agent(recipient, payload_json)

                # 动态推断目录与分配工具权限
                # 同时检查 sink_details 和 route_details
                sink_file = env.get("payload", {}).get("sink_details", {}).get("filepath", "")
                if not sink_file:
                    sink_file = env.get("payload", {}).get("route_details", {}).get("handler_file", "")
                target_cwd = self._get_service_dir(sink_file) # 局部空投：进入微服务子目录
                allowed_tools = "lsp,read,codesearch" # 开启重型武器 lsp

                # 通过 Server Pool 获取端口
                port = await self.server_manager.get_or_start_server(target_cwd)

                # 使用上下文管理器确保资源释放
                async with OpenCodeAgent(port=port, timeout=MAX_AGENT_TIMEOUT) as agent:
                    # 设置 tracker
                    agent.set_session_tracker(self.tracker)
                    agent.set_current_task(env["task_id"])
                    
                    result = await agent.execute(prompt, allowed_tools=allowed_tools)

                logging.info(f"Agent {recipient} 执行完成。输出: {result}")

                tokens_used = result.pop('_tokens', 0)
                if tokens_used > 0:
                    self.tracker.add_tokens(tokens_used)
                    logging.info(f"Agent {recipient} 消耗了 {tokens_used} tokens")

                self.router.route(filepath, result)
                self.bus.mark_completed(filepath, result)
                self.tracker.agent_finish(env["task_id"])
                logging.info(f"Agent {recipient} 已完成任务 {env['task_id']}")
            except Exception as e:
                logging.error(f"处理消息失败 {filepath}: {e}", exc_info=True)

    async def _handle_cross_service_reinstantiation(self, env: dict, filepath: str):
        """接管跨界请求：按 (protocol, target_identifier) 去重共享接力追踪结果。

        缓存语义：
        - 首个发起者为 owner，负责实际拉起所有微服务的接力 ReverseTracer。
        - 同 key 的并发/后续请求共享同一个 Future，命中后只重放 VulnCandidate 写入。
        - owner 失败时从缓存中移除该 key，允许后续请求重试。
        """
        payload = env["payload"]
        task_id = env["task_id"]
        protocol = payload.get("protocol", "HTTP")
        target_id = payload.get("target_identifier", "unknown")
        cache_key = (protocol, target_id)

        # in-flight coalescing：决定本次是 owner 还是 follower
        async with self._cross_service_cache_lock:
            future = self._cross_service_cache.get(cache_key)
            is_owner = future is None
            if is_owner:
                future = asyncio.get_event_loop().create_future()
                self._cross_service_cache[cache_key] = future

        if is_owner:
            logging.info(f"引擎接管跨界请求: 全局搜寻 {protocol} -> '{target_id}' 的调用方 (task={task_id})")
            try:
                relay_results = await self._compute_cross_service_results(env, payload)
                future.set_result(relay_results)
            except Exception as e:
                logging.error(f"跨界追踪 {cache_key} 计算失败: {e}", exc_info=True)
                future.set_exception(e)
                # owner 失败：清出缓存，允许后来者重试
                async with self._cross_service_cache_lock:
                    self._cross_service_cache.pop(cache_key, None)
                self.bus.mark_failed(filepath)
                return
        else:
            logging.info(f"跨界追踪命中缓存 {cache_key} (task={task_id})，复用 owner 结果")
            try:
                relay_results = await future
            except Exception:
                # owner 已失败，本次请求也算失败
                self.bus.mark_failed(filepath)
                return

        # 派发 VulnCandidate：每个命中的微服务都注入一条新任务，task_id 带本请求 base
        hit_count = 0
        for service_name, parsed_result in relay_results.items():
            if parsed_result is None:
                continue
            self.tracker.add_task()
            self.bus.write_message(
                message_type="VulnCandidate",
                task_id=f"{task_id}_HIT_{service_name}",
                sender="ReverseTracer",
                recipient="RedValidator",
                payload=parsed_result,
            )
            hit_count += 1

        self.bus.mark_completed(filepath, {
            "status": "DISPATCHED_GLOBALLY",
            "cache_hit": not is_owner,
            "services_searched": len(relay_results),
            "hits": hit_count,
        })

    async def _compute_cross_service_results(
        self, env: dict, payload: dict
    ) -> Dict[str, Optional[dict]]:
        """实际执行：在所有微服务沙盒中并发拉起接力 ReverseTracer，收集 parsed_result。

        返回 {service_name: parsed_result_or_None}。None 表示该服务返回 NOT_EXPLOITABLE 或解析异常。
        本方法不写总线，写入由调用方负责，以便缓存命中时复用结果。
        """
        protocol = payload.get("protocol", "HTTP")
        target_id = payload.get("target_identifier", "unknown")

        if self.service_route_map:
            service_dirs = [Path(d) for d in self.service_route_map.values()]
        else:
            root_path = Path(self.target_source_dir)
            service_dirs = [d for d in root_path.iterdir() if d.is_dir() and not d.name.startswith('.')]

        if not service_dirs:
            logging.warning("未发现其他微服务目录，跨界追踪终止。")
            return {}

        original_sink_details = env.get("payload", {}).get("sink_details", {})
        historical_chain = payload.get("historical_chain", [])

        relay_payload = {
            "action": "trace_call_chain",
            "sink_details": {
                "vuln_class": payload.get("vuln_type", "CROSS_SERVICE_VULN"),
                "filepath": original_sink_details.get("filepath") or f"{protocol}://{target_id}",
                "line_number": original_sink_details.get("line_number", 0),
                "taint_variable": payload.get("taint_variable", "payload"),
                "cwe": original_sink_details.get("cwe", []),
                "check_id": original_sink_details.get("check_id", ""),
                "severity": original_sink_details.get("severity", "WARNING"),
                "end_line": original_sink_details.get("end_line", 0),
                "column": original_sink_details.get("column", 1),
                "end_column": original_sink_details.get("end_column", 1),
                "dangerous_code": original_sink_details.get("dangerous_code", ""),
                "message": original_sink_details.get("message", "")
            },
            "historical_chain": historical_chain,
            "cross_service_info": {
                "protocol": protocol,
                "target_identifier": target_id
            }
        }
        prompt = self._get_prompt_for_agent(
            "ReverseTracer",
            json.dumps(relay_payload, ensure_ascii=False)
        )

        coros = [
            self._run_relay_agent(str(sd), prompt, sd.name)
            for sd in service_dirs
        ]
        gathered = await asyncio.gather(*coros, return_exceptions=True)

        output: Dict[str, Optional[dict]] = {}
        for sd, res in zip(service_dirs, gathered):
            if isinstance(res, Exception):
                logging.error(f"微服务 [{sd.name}] 接力追踪异常: {res}")
                output[sd.name] = None
            else:
                output[sd.name] = res  # parsed_result 或 None
        return output

    async def _run_relay_agent(
        self, service_dir: str, prompt: str, service_name: str
    ) -> Optional[dict]:
        """在指定微服务目录异地执行接力 ReverseTracer。

        返回：parsed_result（贯通成功）或 None（NOT_EXPLOITABLE / 无链路）。
        异常向上抛出，由调用方 gather(return_exceptions=True) 汇总。
        """
        logging.info(f"在微服务 [{service_name}] 异地拉起溯源特工...")
        port = await self.server_manager.get_or_start_server(service_dir)
        async with OpenCodeAgent(port=port, timeout=MAX_AGENT_TIMEOUT) as agent:
            result = await agent.execute(prompt, allowed_tools="lsp,read,codesearch")
        tokens_used = result.pop('_tokens', 0)
        if tokens_used > 0:
            self.tracker.add_tokens(tokens_used)

        parsed_result = result
        if isinstance(result, dict) and "response" in result:
            try:
                parsed_result = json.loads(result["response"])
            except json.JSONDecodeError:
                parsed_result = result

        if parsed_result.get("status") == "NOT_EXPLOITABLE":
            logging.debug(f"微服务 [{service_name}] 中未发现调用链路。")
            return None

        logging.info(f"微服务 [{service_name}] 成功接力并贯通外网入口！")
        return parsed_result

    async def run(self):
        try:
            logging.info("正在启动代码审计引擎...")
            is_fresh_start = all(len(os.listdir(d)) == 0 for d in [
                self.bus.pending_dir, self.bus.processing_dir, self.bus.completed_dir, self.bus.help_req_dir
            ])

            if is_fresh_start:
                # 发现微服务
                self.service_route_map = self._discover_microservices()
                
                # 直接调用 Semgrep 扫描
                logging.info("开始 Semgrep 扫描...")
                scanner = SemgrepScanner(self.target_source_dir, rules_path=self.semgrep_rules)
                scan_result = scanner.scan()
                
                # 分发扫描结果
                self._dispatch_scan_results("TASK-INIT-001", scan_result)
                logging.info("已注入初始扫描任务。")

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
