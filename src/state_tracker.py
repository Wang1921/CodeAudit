import time
import threading
import json
import logging
import logging.handlers
import asyncio
import aiohttp
from http.server import HTTPServer, SimpleHTTPRequestHandler
import os
from pathlib import Path

class TrackerHandler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass # 禁用 HTTP 请求日志

    def do_GET(self):
        if self.path == '/state.json':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            # 从内存中读取数据
            tracker = getattr(self.server, 'tracker', None)
            if tracker:
                with tracker._lock:
                    state_json = json.dumps(tracker.state)
            else:
                state_json = "{}"
            self.wfile.write(state_json.encode('utf-8'))
        elif self.path == '/' or self.path == '/index.html':
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            
            project_root = Path(__file__).parent.parent
            html_path = project_root / 'web' / 'index.html'
            try:
                with open(html_path, 'r', encoding='utf-8') as f:
                    self.wfile.write(f.read().encode('utf-8'))
            except FileNotFoundError:
                self.wfile.write(b"HTML Dashboard not found.")
        elif self.path == '/reports.html':
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            
            project_root = Path(__file__).parent.parent
            html_path = project_root / 'web' / 'vulnerability-dashboard.html'
            try:
                with open(html_path, 'r', encoding='utf-8') as f:
                    self.wfile.write(f.read().encode('utf-8'))
            except FileNotFoundError:
                self.wfile.write(b"Vulnerability Dashboard not found.")
        elif self.path == '/reports/list.json':
            self.send_response(200)
            self.send_header('Content-type', 'application/json; charset=utf-8')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            tracker = getattr(self.server, 'tracker', None)
            if tracker:
                reports_data = tracker._aggregate_reports()
                self.wfile.write(json.dumps(reports_data, ensure_ascii=False, indent=2).encode('utf-8'))
            else:
                self.wfile.write(json.dumps({"reports": []}).encode('utf-8'))
        else:
            self.send_error(404, "File not found")

class StateTracker:
    def __init__(self, target_dir, port=8080):
        self.state = {
            "target": target_dir,
            "progress": 0,
            "tokens": 0,
            "vulns": {"critical": 0, "high": 0},
            "agents": [],
            "kanban": {
                "suspicious": [],
                "red": [],
                "blue": [],
                "resolved": []
            },
            "logs": [],
            "session_registry": {}
        }
        self._lock = threading.Lock()
        
        self.total_tasks = 1
        self.completed_tasks = 0
        
        self.port = port
        class ReusableHTTPServer(HTTPServer):
            allow_reuse_address = True
            tracker = None
            
        try:
            self.server = ReusableHTTPServer(('0.0.0.0', self.port), TrackerHandler)
        except OSError:
            self.port += 1
            self.server = ReusableHTTPServer(('0.0.0.0', self.port), TrackerHandler)
            
        self.server.tracker = self
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()
        
        logging.info(f"前端大屏已启动，请在浏览器中打开 http://127.0.0.1:{self.port}/")
        
        # 设置日志拦截
        self._setup_logging()
        
        # 启动会话状态轮询任务
        self._start_session_poller()

    def _setup_logging(self):
        class StateLogHandler(logging.Handler):
            def __init__(self, tracker):
                super().__init__()
                self.tracker = tracker
            
            def emit(self, record):
                try:
                    msg = self.format(record)
                    self.tracker.add_log(msg, record.levelname)
                except Exception:
                    self.handleError(record)
        
        formatter = logging.Formatter('[%(name)s] %(message)s')
        handler = StateLogHandler(self)
        handler.setFormatter(formatter)
        logging.getLogger().addHandler(handler)
        
        log_dir = Path(self.state["target"]) / ".a2a_logs"
        try:
            log_dir.mkdir(exist_ok=True)
            file_handler = logging.handlers.RotatingFileHandler(
                log_dir / "audit.log",
                maxBytes=10*1024*1024,
                backupCount=5,
                encoding='utf-8'
            )
            file_handler.setFormatter(logging.Formatter(
                '[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            ))
            logging.getLogger().addHandler(file_handler)
            logging.info(f"日志文件已设置: {log_dir / 'audit.log'}")
        except Exception as e:
            logging.warning(f"无法设置文件日志处理器: {e}")

    def add_log(self, msg, level):
        from datetime import datetime
        with self._lock:
            color = "text-gray-400"
            if level == "ERROR":
                color = "text-red-400"
            elif level == "WARNING":
                color = "text-yellow-400"
            elif level == "INFO":
                color = "text-green-400"
            
            now = datetime.now().strftime('%H:%M:%S')
            self.state["logs"].append({"time": now, "msg": msg, "color": color})
            if len(self.state["logs"]) > 50:
                self.state["logs"].pop(0)

    def agent_start(self, task_id, role, description="处理中"):
        with self._lock:
            # 添加或更新 Agent
            agent = next((a for a in self.state["agents"] if a["id"] == task_id), None)
            if not agent:
                self.state["agents"].append({
                    "id": task_id,
                    "role": role,
                    "task": description,
                    "time": 0,
                    "statusColor": "bg-green-500 pulse-green",
                    "start_time": time.time()
                })

    def update_agent_times(self):
        import time
        with self._lock:
            now = time.time()
            for agent in self.state["agents"]:
                if "start_time" in agent:
                    agent["time"] = int(now - agent["start_time"])

    def agent_finish(self, task_id):
        with self._lock:
            self.completed_tasks += 1
            self.state["progress"] = min(100, int((self.completed_tasks / max(1, self.total_tasks)) * 100))
            self.state["agents"] = [a for a in self.state["agents"] if a["id"] != task_id]

    def add_task(self):
        with self._lock:
            self.total_tasks += 1
            self.state["progress"] = min(100, int((self.completed_tasks / max(1, self.total_tasks)) * 100))

    def update_kanban(self, category, item_id, item_type, route, status="PENDING", details=None):
        with self._lock:
            item = {"id": item_id, "type": item_type, "route": route}
            if category == "resolved":
                item["status"] = status
                if status == "CONFIRMED":
                    self.state["vulns"]["high"] += 1
            
            # 添加完整的漏洞详情
            if details:
                item.update(details)
            
            # 从其他类别中移除
            for cat in self.state["kanban"].values():
                cat[:] = [i for i in cat if i["id"] != item_id]
                
            self.state["kanban"][category].append(item)

    def update_kanban_item(self, item_id, details):
        with self._lock:
            # 在所有类别中查找并更新该项目
            for category in self.state["kanban"].values():
                for item in category:
                    if item.get("id") == item_id:
                        # 更新详情
                        if details:
                            item.update(details)
                        return True
            return False

    def add_tokens(self, tokens: int):
        with self._lock:
            self.state["tokens"] += tokens

    def track_session(self, task_id: str, session_id: str, port: int, hostname: str = "127.0.0.1"):
        """注册新的会话追踪"""
        with self._lock:
            self.state["session_registry"][task_id] = {
                "session_id": session_id,
                "server_port": port,
                "hostname": hostname,
                "status": "busy",
                "last_updated": time.time(),
                "last_message_fetch": 0,
                "messages": [],
                "tools_used": [],
                "tokens": {"total": 0, "input": 0, "output": 0, "reasoning": 0}
            }
        logging.info(f"开始追踪会话: task_id={task_id}, session_id={session_id}, port={port}")

    def untrack_session(self, task_id: str):
        """取消追踪会话"""
        with self._lock:
            if task_id in self.state["session_registry"]:
                del self.state["session_registry"][task_id]
        logging.info(f"停止追踪会话: task_id={task_id}")

    async def update_sessions_from_opencode(self):
        """后台任务：从 OpenCode Server 拉取会话状态和消息"""
        sessions = self.state["session_registry"].copy()
        
        for task_id, session_info in sessions.items():
            try:
                base_url = f"http://{session_info['hostname']}:{session_info['server_port']}"
                
                # 1. 查询会话状态
                status = await self._fetch_session_status(base_url, session_info['session_id'])
                
                # 2. 查询消息历史 (每隔 5 秒查询一次，避免过频)
                current_time = time.time()
                if current_time - session_info.get('last_message_fetch', 0) > 5:
                    messages = await self._fetch_session_messages(base_url, session_info['session_id'])
                    tools = self._extract_tool_calls(messages)
                    tokens = self._extract_tokens(messages)
                    
                    with self._lock:
                        if task_id in self.state["session_registry"]:
                            self.state["session_registry"][task_id]["messages"] = messages
                            self.state["session_registry"][task_id]["tools_used"] = tools
                            self.state["session_registry"][task_id]["tokens"] = tokens
                            self.state["session_registry"][task_id]["last_message_fetch"] = current_time
                
                # 更新状态
                with self._lock:
                    if task_id in self.state["session_registry"]:
                        self.state["session_registry"][task_id]["status"] = status.get("type", "idle")
                        self.state["session_registry"][task_id]["last_updated"] = current_time
                
            except Exception as e:
                logging.warning(f"更新会话状态失败 {task_id}: {e}")

    async def _fetch_session_status(self, base_url: str, session_id: str) -> dict:
        """获取单个会话状态"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{base_url}/session/status", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        all_status = await resp.json()
                        return all_status.get(session_id, {})
        except Exception:
            pass
        return {}

    async def _fetch_session_messages(self, base_url: str, session_id: str, limit: int = 20) -> list:
        """获取会话消息历史"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{base_url}/session/{session_id}/message?limit={limit}", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        return await resp.json()
        except Exception:
            pass
        return []

    def _extract_tool_calls(self, messages: list) -> list:
        """
        保留此方法以保持向后兼容，但返回空列表。
        工具调用信息现在直接在 Message History 中的 tool 类型 part 中显示。
        这样可以避免数据重复，并在消息历史中提供统一的时间线视图。
        """
        return []

    def _extract_tokens(self, messages: list) -> dict:
        """从消息中提取 Token 使用情况"""
        total_tokens = {"total": 0, "input": 0, "output": 0, "reasoning": 0}
        for msg in messages:
            info = msg.get("info", {})
            tokens = info.get("tokens", {})
            total_tokens["input"] += tokens.get("input", 0)
            total_tokens["output"] += tokens.get("output", 0)
            total_tokens["reasoning"] += tokens.get("reasoning", 0)
        total_tokens["total"] = total_tokens["input"] + total_tokens["output"] + total_tokens["reasoning"]
        return total_tokens

    def _start_session_poller(self):
        """启动会话状态轮询任务"""
        def poll_loop():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                while True:
                    loop.run_until_complete(self.update_sessions_from_opencode())
                    time.sleep(2)
            except Exception as e:
                logging.error(f"会话轮询任务异常: {e}")
            finally:
                loop.close()
        
        poll_thread = threading.Thread(target=poll_loop, daemon=True)
        poll_thread.start()
        logging.info("会话状态轮询任务已启动")

    def _extract_service_name(self, task_id: str) -> str:
        """从 task_id 中提取微服务名称"""
        if not task_id:
            return 'unknown'
        
        task_id_upper = task_id.upper()
        
        # 规则1: 从 TRACE_CROSS_HIT 提取（最高优先级）
        if 'TRACE_CROSS_HIT_' in task_id_upper:
            parts = task_id.split('TRACE_CROSS_HIT_')
            if len(parts) > 1:
                rest = parts[1]
                # 提取 service 部分，直到遇到数字或时间戳
                service_parts = []
                for part in rest.split('_'):
                    if part.isdigit() or '-' in part:  # 遇到数字或时间戳就停止
                        break
                    service_parts.append(part)
                service = '-'.join(service_parts)
                if service and service not in ['TRACE', 'CROSS', 'HIT']:
                    return service.lower()
        
        # 规则2: 从 _SERVICE_ 提取
        if '_SERVICE_' in task_id_upper:
            parts = task_id.split('_SERVICE_')
            if len(parts) > 1:
                return parts[1].split('_')[0].lower()
        
        # 规则3: 从 task_id 中查找常见服务名模式
        common_services = ['user-service', 'admin-service', 'api-service', 'processor-service', 'eval-service', 'auth-service']
        for service in common_services:
            if service.upper() in task_id_upper:
                return service
        
        # 规则4: 从 task_id 中提取类似 xxx-service 的模式
        import re
        matches = re.findall(r'([a-z]+-service)', task_id.lower())
        if matches:
            return matches[0]
        
        # 默认值
        return 'unknown'
        
        task_id_upper = task_id.upper()
        
        # 规则1: 从 TRACE_CROSS_HIT 提取
        if 'TRACE_CROSS_HIT_' in task_id_upper:
            parts = task_id.upper().split('TRACE_CROSS_HIT_')
            if len(parts) > 1:
                service = parts[1].split('_')[0]
                if service:
                    return service.lower()
        
        # 规则2: 从 _SERVICE_ 提取
        if '_SERVICE_' in task_id_upper:
            parts = task_id_upper.split('_SERVICE_')
            if len(parts) > 1:
                service = parts[1].split('_')[0]
                if service:
                    return service.lower()
        
        # 规则3: 从 ROUTE_ 或 SINK_ 之后提取
        for marker in ['_ROUTE_', '_SINK_']:
            if marker in task_id_upper:
                parts = task_id_upper.split(marker)
                if len(parts) > 1:
                    service = parts[1].split('_')[0]
                    if service and service not in ['TRACE', 'CROSS', 'HIT']:
                        return service.lower()
        
        # 规则4: 从 task_id 中查找常见服务名模式
        common_services = ['user-service', 'admin-service', 'api-service', 'processor-service', 'eval-service', 'auth-service']
        for service in common_services:
            if service.upper() in task_id_upper:
                return service
        
        # 默认值
        return 'unknown'

    def _extract_file_location(self, report: dict) -> tuple:
        """从报告中提取文件路径和行号"""
        import re
        
        # 优先级1: 从 description 正则提取（最可靠）
        desc = report.get('description', '')
        # 提取完整路径 "xxx/xxx/xxx.java:123" 模式
        full_path_matches = re.findall(r'([/\w\-.]+\.java):(\d+)', desc)
        if full_path_matches:
            return full_path_matches[0][0], full_path_matches[0][1]
        
        # 提取简单文件名 "xxx.java:123" 模式
        simple_matches = re.findall(r'(\w+\.java):(\d+)', desc)
        if simple_matches:
            return simple_matches[0][0], simple_matches[0][1]
        
        # 提取任何包含 .java 的路径
        java_matches = re.findall(r'([/\w\-.]+\.java)', desc)
        if java_matches:
            return java_matches[0], None
        
        # 优先级2: 从 call_chain 中查找格式为 "ClassName.method:行号" 的元素
        call_chain = report.get('call_chain', [])
        for item in call_chain:
            item_str = str(item)
            # 去除编号前缀（如 "1. "）
            item_str = re.sub(r'^\d+\.\s*', '', item_str)
            
            # 查找方法调用格式：Class.method:行号
            if ':' in item_str and '(' not in item_str:
                parts = item_str.split(':')
                if len(parts) == 2:
                    filepath = parts[0].strip()
                    line_number = parts[1].strip()
                    
                    # 确保 filepath 不是太长且 line_number 是数字
                    if len(filepath) < 100 and line_number.isdigit():
                        return filepath, line_number
        
        # 优先级3: 从 call_chain 中提取 Java 类名和方法
        for item in call_chain:
            item_str = str(item)
            # 去除编号前缀
            item_str = re.sub(r'^\d+\.\s*', '', item_str)
            
            # 查找 "Controller: ClassName.method(...)" 格式
            if 'Controller:' in item_str or 'Service:' in item_str:
                # 提取方法调用部分
                method_match = re.search(r'(\w+)\.(\w+)\s*\(', item_str)
                if method_match:
                    class_name = method_match.group(1)
                    method_name = method_match.group(2)
                    return f'{class_name}.{method_name}', None
            
            # 查找简单的类名.方法名格式
            method_match = re.search(r'(\w+\.\w+)\(.*?\)', item_str)
            if method_match:
                return method_match.group(1), None
        
        # 优先级4: 提取任何包含 .java 的片段
        for item in call_chain:
            if '.java' in str(item):
                java_file = re.search(r'(\w+\.java)', str(item))
                if java_file:
                    return java_file.group(1), None
        
        # 默认值
        return None, None

    def _parse_vulnerability_report(self, report: dict) -> dict:
        """解析并增强漏洞报告，补充缺失字段"""
        if not report:
            return {}
        
        task_id = report.get('task_id', '')
        
        # 提取 service_name
        if 'service_name' not in report or not report['service_name']:
            report['service_name'] = self._extract_service_name(task_id)
        
        # 提取 filepath 和 line_number
        if 'filepath' not in report or not report['filepath']:
            filepath, line_number = self._extract_file_location(report)
            report['filepath'] = filepath or 'N/A'
            report['line_number'] = line_number or '-'
        
        # 确保 entry_route 有值
        if 'entry_route' not in report or not report['entry_route'] or report['entry_route'] == '未知':
            # 尝试从 description 中提取路由信息
            desc = report.get('description', '')
            import re
            route_match = re.search(r'/api/[\w\-]+', desc)
            if route_match:
                report['entry_route'] = f'GET/POST {route_match.group(0)}'
            else:
                report['entry_route'] = 'Unknown'
        
        # 确保其他可选字段都有默认值
        optional_fields = [
            'suspicion_reason', 'attack_vector', 'defense_analysis', 
            'mitigation_advice', 'poc_payload', 'max_impact'
        ]
        for field in optional_fields:
            if field not in report:
                report[field] = ''
        
        # 确保 call_chain 是列表
        if 'call_chain' not in report or not isinstance(report['call_chain'], list):
            report['call_chain'] = []
        
        return report

    def _aggregate_reports(self) -> dict:
        """聚合所有漏洞报告"""
        project_root = Path(__file__).parent.parent
        reports_dir = project_root / "reports"
        
        if not reports_dir.exists():
            return {"reports": []}
        
        all_reports = []
        
        try:
            # 扫描所有 vulnerability_*.json 文件
            for json_file in sorted(reports_dir.glob("vulnerability_*.json")):
                try:
                    with open(json_file, 'r', encoding='utf-8') as f:
                        report = json.load(f)
                    
                    # 解析并增强报告
                    enhanced_report = self._parse_vulnerability_report(report)
                    all_reports.append(enhanced_report)
                    
                except json.JSONDecodeError as e:
                    logging.warning(f"解析报告文件失败 {json_file.name}: {e}")
                except Exception as e:
                    logging.warning(f"读取报告文件失败 {json_file.name}: {e}")
        
        except Exception as e:
            logging.error(f"扫描报告目录失败: {e}")
        
        return {"reports": all_reports}
