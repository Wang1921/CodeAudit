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
        """从消息中提取工具调用记录"""
        tools = []
        for msg in messages:
            for part in msg.get("parts", []):
                if part.get("type") == "tool":
                    tools.append({
                        "name": part.get("name"),
                        "input": str(part.get("input", ""))[:100],
                        "output": str(part.get("output", ""))[:100],
                        "timestamp": msg.get("info", {}).get("time", {}).get("created")
                    })
        return tools

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
