import time
import threading
import json
import logging
from http.server import HTTPServer, SimpleHTTPRequestHandler
import os
from pathlib import Path

class TrackerHandler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass # Disable logging for HTTP requests

    def do_GET(self):
        if self.path == '/state.json':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            # Read from memory
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
            "logs": []
        }
        self._lock = threading.Lock()
        
        self.total_tasks = 1
        self.completed_tasks = 0
        
        self.port = port
        class ReusableHTTPServer(HTTPServer):
            allow_reuse_address = True
            
        try:
            self.server = ReusableHTTPServer(('0.0.0.0', self.port), TrackerHandler)
        except OSError:
            self.port += 1
            self.server = ReusableHTTPServer(('0.0.0.0', self.port), TrackerHandler)
            
        self.server.tracker = self
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()
        
        logging.info(f"Dashboard started. Open http://127.0.0.1:{self.port}/ in your browser.")
        
        # Setup log interception
        self._setup_logging()

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

    def agent_start(self, task_id, role, description="Processing"):
        with self._lock:
            # Add or update agent
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

    def update_kanban(self, category, item_id, item_type, route, status="PENDING"):
        with self._lock:
            item = {"id": item_id, "type": item_type, "route": route}
            if category == "resolved":
                item["status"] = status
                if status == "CONFIRMED":
                    self.state["vulns"]["high"] += 1
            
            # Remove from other categories
            for cat in self.state["kanban"].values():
                cat[:] = [i for i in cat if i["id"] != item_id]
                
            self.state["kanban"][category].append(item)
