import asyncio
import json
import logging
import os
import platform
import time
from pathlib import Path

from src import prompts
from src.a2a_bus import A2ABusManager
from src.claude_agent import ClaudeAgent
from src.semgrep_scanner import SemgrepScanner
from src.claude_manager import ClaudeAgentManager
from src.state_router import StateRouter
from src.state_tracker import StateTracker

MAX_CONCURRENT_AGENTS = 5     # 初始 Semgrep 派发任务的并发上限
MAX_CHAIN_AGENTS = 3          # 链路续接（Reverse→Red→Blue 等）的专用并发上限

class AuditEngine:
    def __init__(self, target_source_dir: str, semgrep_rules: str | None = None):
        self.tracker = StateTracker(target_source_dir)
        self.bus = A2ABusManager(target_source_dir)
        self.router = StateRouter(self.bus, self.tracker, target_source_dir)
        self.target_source_dir = target_source_dir
        self.semgrep_rules = semgrep_rules
        # 主 semaphore 给初始 Semgrep 派发用；chain_semaphore 给所有非 SemgrepScanner 发出的
        # 续接消息用 —— 避免 100+ 初始任务把 FIFO 队列填满后续接消息饿死。
        self.semaphore = asyncio.Semaphore(MAX_CONCURRENT_AGENTS)
        self.chain_semaphore = asyncio.Semaphore(MAX_CHAIN_AGENTS)
        # 全局服务路由字典：service_name -> service_root_dir
        self.service_route_map: dict = {}
        # Claude Agent 管理器
        self.agent_manager = ClaudeAgentManager(max_active=MAX_CONCURRENT_AGENTS)
        # 跨微服务追踪结果缓存：(protocol, target_identifier) -> Future[Dict[service_name, parsed_result|None]]
        # 使用 Future 实现 in-flight coalescing：并发同 key 请求共享同一次计算
        self._cross_service_cache: dict[tuple[str, str], asyncio.Future] = {}
        self._cross_service_cache_lock = asyncio.Lock()

    def _get_service_dir(self, filepath: str) -> str:
        """根据文件路径，推断其所属的微服务根目录。
        优先从已发现的服务映射表中查找，
        回退到启发式逻辑：寻找包含 pom.xml / go.mod / package.json 的最近父目录。
        """
        if not filepath:
            return self.target_source_dir

        # 归一化为绝对路径：Semgrep 对 sink 给的是相对路径，对 route 给的是绝对路径
        abs_filepath = filepath if os.path.isabs(filepath) else os.path.join(self.target_source_dir, filepath)
        abs_filepath = os.path.normpath(abs_filepath)

        # 优先使用已发现的服务映射表；用带分隔符的前缀匹配避免 "api" 误匹配 "api-gateway"
        if self.service_route_map:
            best_match: tuple[str, str] | None = None  # (service_name, service_dir)
            for service_name, service_dir in self.service_route_map.items():
                normalized_dir = os.path.normpath(service_dir)
                prefix = normalized_dir + os.sep
                if abs_filepath == normalized_dir or abs_filepath.startswith(prefix):
                    # 选最长匹配（处理嵌套服务目录）
                    if best_match is None or len(normalized_dir) > len(best_match[1]):
                        best_match = (service_name, normalized_dir)
            if best_match:
                logging.debug(f"[ServiceDir] '{filepath}' 归属微服务 '{best_match[0]}' -> {best_match[1]}")
                return best_match[1]

        # 启发式回退：从文件所在目录逐级向上查找构建文件
        build_markers = ("pom.xml", "go.mod", "package.json", "build.gradle")
        root_abs = os.path.normpath(self.target_source_dir)
        current = os.path.dirname(abs_filepath) if not os.path.isdir(abs_filepath) else abs_filepath
        while current and current.startswith(root_abs) and current != root_abs:
            for marker in build_markers:
                if os.path.exists(os.path.join(current, marker)):
                    logging.debug(f"[ServiceDir] '{filepath}' 启发式识别微服务目录: {current}")
                    return current
            parent = os.path.dirname(current)
            if parent == current:
                break
            current = parent

        logging.debug(f"[ServiceDir] '{filepath}' 未识别到独立微服务目录，使用根目录")
        return self.target_source_dir

    def _get_prompt_for_agent(self, agent_name: str, payload_json: str) -> str:
        """按 recipient agent 名称加载并渲染对应 prompt 模板。

        ReportGenerator 已退化为纯 Python 字段映射（见 state_router._build_report_fields），
        不再走 LLM；对未知 agent 抛 ValueError，避免误派发到没有 prompt 的角色。
        """
        if agent_name == "ReverseTracer":
            return prompts.format_reverse_tracer_prompt(payload_json)
        elif agent_name == "LogicAuditor":
            return prompts.format_logic_auditor_prompt(payload_json)
        elif agent_name == "RedValidator":
            return prompts.format_red_validator_prompt(payload_json)
        elif agent_name == "BlueValidator":
            return prompts.format_blue_validator_prompt(payload_json)
        elif agent_name == "ConfigValidator":
            return prompts.format_config_validator_prompt(payload_json)
        elif agent_name == "CrossServicePrefilter":
            return prompts.format_cross_service_prefilter_prompt(payload_json)
        else:
            # ReportGenerator 已改为纯 Python 字段映射（state_router._build_report_fields），不再是 LLM agent
            raise ValueError(f"未知的 Agent 类型: {agent_name}")

    # 微服务构建文件：命中任一才认为子目录是独立服务。
    # 避免 BenchmarkJava 这类单项目的 scorecard/results/VMs 等普通目录被误判为微服务，
    # 从而在跨服务 fan-out 时被重复拉起造成漏洞重复上报。
    _BUILD_MARKERS = (
        "pom.xml", "build.gradle", "build.gradle.kts",  # Java/Kotlin
        "package.json",                                   # Node.js
        "go.mod",                                         # Go
        "Cargo.toml",                                     # Rust
        "requirements.txt", "pyproject.toml", "setup.py", # Python
        "composer.json",                                  # PHP
        "Gemfile",                                        # Ruby
        "mix.exs",                                        # Elixir
    )

    def _discover_microservices(self) -> dict:
        """扫描目标目录的第一层子目录，识别**真正独立**的微服务。

        策略（严格）：只有**自身含构建文件**且根目录**不含**构建文件的子目录才算微服务；
        否则视为单项目（所有代码属于同一个"main"服务，避免跨服务 fan-out 重复上报）。

        设计动机：在 BenchmarkJava 这类单项目上，`scorecard / results / VMs / scripts`
        等普通顶层子目录会被旧版启发式误认为微服务，导致一次跨服务 fan-out 产生 N 份
        重复报告。加构建文件门槛后，只有真正的多服务仓库（如 `user-service/pom.xml`、
        `order-service/pom.xml`）才会触发 fan-out。
        """
        service_map = {}
        root_path = Path(self.target_source_dir)

        if not root_path.exists():
            logging.warning(f"目标目录不存在: {self.target_source_dir}")
            return service_map

        # 若根目录自带构建文件（单项目常见），整仓视为一个服务，不再细分
        root_has_build = any((root_path / m).exists() for m in self._BUILD_MARKERS)
        if root_has_build:
            logging.info(
                f"[ServiceDiscovery] 根目录发现构建文件，按单项目处理 "
                f"({', '.join(m for m in self._BUILD_MARKERS if (root_path / m).exists())})"
            )
            service_map["main"] = self.target_source_dir
            return service_map

        # 根目录无构建文件 → 检查每个一级子目录是否自带构建文件
        skipped = []
        for entry in root_path.iterdir():
            if not entry.is_dir() or entry.name.startswith('.'):
                continue
            has_marker = any((entry / m).exists() for m in self._BUILD_MARKERS)
            if has_marker:
                service_map[entry.name] = str(entry)
            else:
                skipped.append(entry.name)

        if service_map:
            logging.info(
                f"[ServiceDiscovery] 发现 {len(service_map)} 个微服务: {list(service_map.keys())}"
            )
            if skipped:
                logging.debug(
                    f"[ServiceDiscovery] 跳过 {len(skipped)} 个无构建文件的子目录: {skipped}"
                )
        else:
            logging.info(
                "[ServiceDiscovery] 根目录及一级子目录均无构建文件，按单项目处理"
            )
            service_map["main"] = self.target_source_dir

        return service_map

    @staticmethod
    def _deduplicate(items: list, key_fn, kind: str) -> list:
        """按 key_fn 产出的元组去重，保留首次出现的条目。kind 仅用于日志。"""
        seen = set()
        unique = []
        for item in items:
            key = key_fn(item)
            if key in seen:
                continue
            seen.add(key)
            unique.append(item)
        dropped = len(items) - len(unique)
        if dropped > 0:
            logging.info(f"[Dedupe] {kind}: {len(items)} → {len(unique)}（丢弃 {dropped} 条重复）")
        return unique

    def _dispatch_scan_results(self, task_id: str, scan_result: dict):
        """分发 Semgrep 扫描结果到各个 Agent（入口统一去重，避免同一 sink/route 被多规则命中重复派发）"""

        # 去重：sinks 以 (vuln_class, filepath, line) 为 key，处理嵌套表达式 / 多规则同行命中
        sinks_raw = scan_result.get("sinks", [])
        sinks = self._deduplicate(
            sinks_raw,
            key_fn=lambda s: (
                s.get("sink_details", {}).get("vuln_class", ""),
                s.get("sink_details", {}).get("filepath", ""),
                s.get("sink_details", {}).get("line_number", 0),
            ),
            kind="sinks",
        )

        # 去重：routes 以 (method, path, handler_file) 为 key，覆盖 spring-api 两条规则的潜在重叠
        routes_raw = scan_result.get("routes", [])
        routes = self._deduplicate(
            routes_raw,
            key_fn=lambda r: (
                r.get("method", ""),
                r.get("path", ""),
                r.get("handler_file", ""),
            ),
            kind="routes",
        )

        # 处理路由结果
        # 注意：payload 中不塞 action 字段 —— 无消费者，且会被 LLM echo 到输出，
        # 诱导写出 prompt 里仅见过的 cross_service_trace 值，误触发跨服务 fan-out。
        for i, route in enumerate(routes):
            self.tracker.add_task()
            self.bus.write_message(
                message_type="TaskRequest",
                task_id=f"{task_id}_ROUTE_{i}",
                sender="SemgrepScanner",
                recipient="LogicAuditor",
                payload={"route_details": route}
            )

        # 处理漏洞点结果（使用上面去重后的 sinks，不要复写为原始数据）
        # taint_required=False 的 sink（弱加密/弱随机/硬编码等无 source→sink 污点链的场景）
        # 走 fast path 直接到 BlueValidator 做静态定性，跳过 ReverseTracer 和 RedValidator。
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

            taint_required = sink_details.get("taint_required", True)
            if taint_required:
                recipient = "ReverseTracer"
                task_suffix = "TRACE"
            else:
                recipient = "ConfigValidator"
                task_suffix = "STATIC"

            self.bus.write_message(
                message_type="TaskRequest",
                task_id=f"{task_id}_SINK_{i}_{task_suffix}",
                sender="SemgrepScanner",
                recipient=recipient,
                payload={"sink_details": sink_details},
            )

    async def process_task(self, filepath: str):
        """处理 A2A 总线上的单条任务消息（一个 .json envelope 文件）。

        职责：
          1. 读取 envelope，按 sender 决定走主 semaphore 还是 chain_semaphore（避免饥饿）。
          2. 拦截 Orchestrator 的跨微服务追踪请求，转给专用 handler 去重处理。
          3. 否则按 recipient 加载 prompt / output_schema / per-agent timeout，
             调 Claude Agent 跑一次 LLM，落库结果并交给 StateRouter 决定后续路由。

        异常处理：所有错误捕获后通过 bus.mark_failed(filepath) 落到 failed/ 目录，
        不抛出，让 dispatcher 继续处理其他任务。
        """
        # 先读 envelope 决定走哪个 semaphore（不计入 LLM 并发，纯本地文件读）
        try:
            env = self.bus.read_message(filepath)
        except Exception as e:
            logging.error(f"读取消息失败 {filepath}: {e}", exc_info=True)
            try:
                if os.path.exists(filepath):
                    self.bus.mark_failed(filepath)
            except Exception:
                pass
            return

        # 链路续接（非 SemgrepScanner 派发）走专用 chain_semaphore，避免被
        # 初始批量派发的任务挤入 FIFO 队列饿死。Sender 是 SemgrepScanner 的初始
        # 派发走主 semaphore；其余（ReverseTracer/LogicAuditor/RedValidator 等）
        # 都是上游 Agent 续接出来的，走 chain_semaphore。
        sender = env.get("sender", "")
        sem = self.semaphore if sender == "SemgrepScanner" else self.chain_semaphore

        async with sem:
            task_id: str | None = None
            recipient: str | None = None
            try:
                recipient = env["recipient"]
                task_id = env.get("task_id")
                payload_json = json.dumps(env["payload"], ensure_ascii=False)

                # 拦截跨微服务异地重拉起请求
                if recipient == "Orchestrator" and env.get("message_type") == "CrossServiceTraceRequest":
                    await self._handle_cross_service_reinstantiation(env, filepath)
                    return

                logging.info(f"Agent {recipient} 开始任务 {task_id}")
                self.tracker.agent_start(task_id, recipient, f"正在处理 {task_id}")
                prompt = self._get_prompt_for_agent(recipient, payload_json)

                # 动态推断目录与分配工具权限
                # 同时检查 sink_details 和 route_details
                sink_file = env.get("payload", {}).get("sink_details", {}).get("filepath", "")
                if not sink_file:
                    sink_file = env.get("payload", {}).get("route_details", {}).get("handler_file", "")
                target_cwd = self._get_service_dir(sink_file) # 局部空投：进入微服务子目录
                allowed_tools = "lsp,read,codesearch" # 开启重型武器 lsp

                # 获取 Claude Agent（自动管理会话）
                agent = await self.agent_manager.get_agent(target_cwd)

                # 设置 session tracker 和 task_id
                agent.set_session_tracker(self.tracker)
                agent.set_current_task(task_id)

                # 加载当前 Agent 的输出 Schema，启用服务端结构化 JSON 校验
                output_schema = prompts.get_output_schema(recipient)

                # 使用 Claude Agent 执行任务
                result = await agent.execute(
                    prompt,
                    allowed_tools=allowed_tools,
                    output_schema=output_schema,
                )

                logging.info(f"Agent {recipient} 执行完成。输出: {result}")

                tokens_used = result.pop('_tokens', 0)
                if tokens_used > 0:
                    self.tracker.add_tokens(tokens_used)
                    logging.info(f"Agent {recipient} 消耗了 {tokens_used} tokens")

                self.router.route(filepath, result)
                self.bus.mark_completed(filepath, result)
                self.tracker.agent_finish(task_id)
                logging.info(f"Agent {recipient} 已完成任务 {task_id}")
            except Exception as e:
                logging.error(f"处理消息失败 {filepath}: {e}", exc_info=True)
                # 让任务离开 processing 目录，并对冲 tracker 计数，避免进度永远卡不满
                try:
                    if os.path.exists(filepath):
                        self.bus.mark_failed(filepath)
                except Exception as move_err:
                    logging.error(f"移动失败任务到 failed/ 目录出错 {filepath}: {move_err}")
                if task_id:
                    try:
                        self.tracker.update_kanban(
                            "resolved", task_id, recipient or "UNKNOWN", "执行异常", status="ERROR"
                        )
                        self.tracker.agent_finish(task_id)
                    except Exception:
                        pass

    async def _handle_cross_service_reinstantiation(self, env: dict, filepath: str):
        """接管跨界请求：按 (protocol, target_identifier) 去重共享接力追踪结果。

        缓存语义：
        - 首个发起者为 owner，负责实际拉起所有微服务的接力 ReverseTracer。
        - 同 key 的并发/后续请求共享同一个 Future，命中后只重放 VulnCandidate 写入。
        - in-flight 期间命中缓存；owner 一旦 set_result/set_exception 就立即清出字典，
          避免 Future 常驻内存以及后续派发拿到陈旧结果。follower 通过局部变量持有 Future，
          不受字典清理影响。
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
                future = asyncio.get_running_loop().create_future()
                self._cross_service_cache[cache_key] = future

        if is_owner:
            logging.info(f"引擎接管跨界请求: 全局搜寻 {protocol} -> '{target_id}' 的调用方 (task={task_id})")
            compute_failed = False
            try:
                relay_results = await self._compute_cross_service_results(env, payload)
                future.set_result(relay_results)
            except Exception as e:
                logging.error(f"跨界追踪 {cache_key} 计算失败: {e}", exc_info=True)
                future.set_exception(e)
                compute_failed = True
            finally:
                # 结果已通过 Future 交付给所有 follower（它们握有局部引用），
                # 字典无需再保留，否则会内存泄漏 + 后续派发复用过期结果。
                async with self._cross_service_cache_lock:
                    self._cross_service_cache.pop(cache_key, None)

            if compute_failed:
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
    ) -> dict[str, dict | None]:
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

        # 预筛选：用轻量 Agent 判断哪些微服务引用了 target_identifier，跳过无关服务
        service_dirs = await self._prefilter_services_with_agent(service_dirs, protocol, target_id)
        if not service_dirs:
            logging.info(f"预筛选后无微服务引用 '{target_id}'，跨界追踪终止。")
            return {}

        original_sink_details = env.get("payload", {}).get("sink_details", {})
        historical_chain = payload.get("historical_chain", [])

        relay_payload = {
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

        output: dict[str, dict | None] = {}
        for sd, res in zip(service_dirs, gathered):
            if isinstance(res, Exception):
                logging.error(f"微服务 [{sd.name}] 接力追踪异常: {res}")
                output[sd.name] = None
            else:
                output[sd.name] = res  # parsed_result 或 None
        return output

    async def _prefilter_services_with_agent(
        self, service_dirs: list[Path], protocol: str, target_identifier: str
    ) -> list[Path]:
        """用轻量 Agent 全局预筛选引用了 target_identifier 的微服务。

        Agent 可以理解间接引用（配置变量、常量定义、注册中心服务名等），
        比纯文本 grep 更准确。解析失败时降级为全量扫描。
        """
        if not target_identifier or target_identifier == "unknown":
            return service_dirs

        if len(service_dirs) <= 1:
            return service_dirs

        try:
            payload = {
                "protocol": protocol,
                "target_identifier": target_identifier,
                "services": [sd.name for sd in service_dirs],
                "project_root": str(self.target_source_dir),
            }
            prompt = prompts.format_cross_service_prefilter_prompt(
                json.dumps(payload, ensure_ascii=False)
            )
            output_schema = prompts.get_output_schema("CrossServicePrefilter")

            agent = await self.agent_manager.get_agent(self.target_source_dir)
            result = await agent.execute(
                prompt,
                allowed_tools="read,codesearch",
                output_schema=output_schema,
            )
            tokens_used = result.pop('_tokens', 0)
            if tokens_used > 0:
                self.tracker.add_tokens(tokens_used)

            relevant = self._extract_prefilter_result(result)
            if relevant is None:
                logging.warning("预筛选 Agent 输出解析失败，降级为全量扫描")
                return service_dirs

            name_to_dir = {sd.name: sd for sd in service_dirs}
            filtered = [name_to_dir[name] for name in relevant if name in name_to_dir]

            if not filtered:
                logging.warning("预筛选 Agent 返回空列表，降级为全量扫描")
                return service_dirs

            logging.info(
                f"预筛选: {len(filtered)}/{len(service_dirs)} 个微服务可能引用了 '{target_identifier}'"
            )
            return filtered
        except Exception as e:
            logging.warning(f"预筛选 Agent 执行异常 ({e})，降级为全量扫描")
            return service_dirs

    @staticmethod
    def _extract_prefilter_result(result: dict | None) -> list[str] | None:
        """从 Agent 输出中提取 relevant_services 列表。"""
        if not result:
            return None

        # 优先取 structured_output
        structured = result.get("structured_output") if isinstance(result, dict) else None
        if isinstance(structured, dict) and "relevant_services" in structured:
            return structured["relevant_services"]

        # 降级：从 response 文本解析 JSON
        response = result.get("response") if isinstance(result, dict) else None
        if isinstance(response, str) and response.strip():
            try:
                parsed = json.loads(response)
                if isinstance(parsed, dict) and "relevant_services" in parsed:
                    return parsed["relevant_services"]
            except json.JSONDecodeError:
                pass

        return None

    async def _run_relay_agent(
        self, service_dir: str, prompt: str, service_name: str
    ) -> dict | None:
        """在指定微服务目录异地执行接力 ReverseTracer。

        返回：parsed_result（贯通成功）或 None（NOT_EXPLOITABLE / 无链路）。
        异常向上抛出，由调用方 gather(return_exceptions=True) 汇总。
        """
        logging.info(f"在微服务 [{service_name}] 异地拉起溯源特工...")
        output_schema = prompts.get_output_schema("ReverseTracer")
        agent = await self.agent_manager.get_agent(service_dir)

        # 设置 session tracker 和 task_id，用于 Turn History 追踪
        task_id = f"RELAY_{service_name}_{int(time.time() * 1000)}"
        agent.set_session_tracker(self.tracker)
        agent.set_current_task(task_id)

        result = await agent.execute(
            prompt,
            allowed_tools="lsp,read,codesearch",
            output_schema=output_schema,
        )
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

    async def _update_tracker_loop(self):
        """后台刷新 Agent 用时显示，随 run() 生命周期一起终止。"""
        try:
            while True:
                self.tracker.update_agent_times()
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            raise

    async def run(self):
        """引擎主循环：发现微服务 → 初始 Semgrep 扫描 → 不断轮询 A2A 总线 dispatch 任务。

        启动顺序：
          1. 若 .a2a_bus 各目录均空（fresh start），先 _discover_microservices() 摊出服务映射，
             按服务数动态扩容沙盒池，再调 SemgrepScanner 灌入第一批任务。
          2. 否则视为 resume，跳过初始扫描直接进入主循环。
          3. 主循环每轮 get_pending_tasks() 取一批 envelope，并发交给 process_task()，
             同时维护 inflight 集合做反压；监测到 pending/processing 全空即收尾。
          4. 收尾阶段做最终 build_summary，关闭沙盒池、tracker 等资源。
        """
        tracker_task: asyncio.Task | None = None
        inflight: set[asyncio.Task] = set()
        try:
            logging.info("正在启动代码审计引擎...")

            # 初始化 CodeGraph 索引
            logging.info("正在初始化 CodeGraph 索引...")
            if platform.system() == "Windows":
                codegraph_proc = await asyncio.create_subprocess_exec(
                    "cmd", "/c", "codegraph", "init", "-i",
                    cwd=self.target_source_dir,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            else:
                codegraph_proc = await asyncio.create_subprocess_exec(
                    "codegraph", "init", "-i",
                    cwd=self.target_source_dir,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            stdout, stderr = await codegraph_proc.communicate()
            if codegraph_proc.returncode == 0:
                logging.info("CodeGraph 索引初始化完成")
            else:
                logging.warning(f"CodeGraph 索引初始化失败: {stderr.decode() if stderr else ''}")

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

            tracker_task = asyncio.create_task(self._update_tracker_loop())

            # 主循环 —— 完成判定:
            # 先 get_pending_tasks() 再检查 inflight。
            # process_task 的顺序是 "写下游消息 → mark_completed → 协程结束"，
            # 所以 "inflight 非空" 或 "pending 非空" 任一成立都说明系统未稳定。
            # 连续 2 轮完全空闲才退出，额外缓冲一次防御极端调度 race。
            idle_ticks = 0
            IDLE_TICKS_TO_EXIT = 2

            while True:
                tasks = self.bus.get_pending_tasks()
                for filepath in tasks:
                    t = asyncio.create_task(self.process_task(filepath))
                    inflight.add(t)
                    t.add_done_callback(inflight.discard)

                if not tasks and not inflight:
                    idle_ticks += 1
                    if idle_ticks >= IDLE_TICKS_TO_EXIT:
                        logging.info("所有任务已完成，引擎正常退出。")
                        break
                else:
                    idle_ticks = 0

                await asyncio.sleep(1)
        finally:
            # 1) 停掉 tracker 后台任务
            if tracker_task is not None and not tracker_task.done():
                tracker_task.cancel()
                try:
                    await tracker_task
                except asyncio.CancelledError:
                    pass
                except Exception as e:
                    logging.error(f"tracker 后台任务退出异常: {e}")

            # 2) 处理在途任务：Ctrl+C 或异常退出时 inflight 可能仍有协程。
            # 优雅等待 5 秒，超时则取消剩余任务。正常退出路径下 inflight 已为空，直接通过。
            if inflight:
                pending_count = len(inflight)
                logging.info(f"等待 {pending_count} 个在途任务收尾（最长 5 秒）...")
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*inflight, return_exceptions=True),
                        timeout=5.0,
                    )
                except asyncio.TimeoutError:
                    still_alive = [t for t in inflight if not t.done()]
                    logging.warning(f"{len(still_alive)} 个在途任务超时未收尾，取消中...")
                    for t in still_alive:
                        t.cancel()
                    await asyncio.gather(*still_alive, return_exceptions=True)

            # 3) 关闭 Agent 管理器
            await self.agent_manager.shutdown_all()

            # 4) 生成汇总报告（reports/SUMMARY.md）
            try:
                from src.build_summary_report import build_summary
                reports_dir = os.path.join(self.target_source_dir, "reports")
                if os.path.isdir(reports_dir):
                    project = os.path.basename(self.target_source_dir.rstrip("/")) or "未命名项目"
                    md = build_summary(reports_dir, self.target_source_dir, project)
                    out_path = os.path.join(reports_dir, "SUMMARY.md")
                    with open(out_path, "w", encoding="utf-8") as f:
                        f.write(md)
                    logging.info(f"汇总报告已生成: {out_path}")
            except Exception as e:
                logging.warning(f"生成汇总报告失败（不影响主流程）: {e}")
