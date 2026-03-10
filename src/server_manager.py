import asyncio
import socket
import logging
import time
import sys
from typing import Dict, Any

class OpenCodeServerManager:
    def __init__(self, max_active_servers: int = 5):
        self.max_active_servers = max_active_servers
        # cwd -> {"process": Process, "port": int, "last_accessed": float}
        self._servers: Dict[str, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()

    def _get_free_port(self) -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            return s.getsockname()[1]

    async def get_or_start_server(self, cwd: str) -> int:
        async with self._lock:
            if cwd in self._servers:
                self._servers[cwd]["last_accessed"] = time.time()
                return self._servers[cwd]["port"]

            if len(self._servers) >= self.max_active_servers:
                await self._evict_oldest_server()

            port = self._get_free_port()
            cmd = ["opencode", "serve", "--port", str(port), "--dir", cwd]
            if sys.platform == "win32":
                cmd[0] = "opencode.exe"

            logging.info(f"🚀 [LRU Pool] 启动常驻沙盒 Server: {cwd} (端口: {port})")

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE
            )
            await asyncio.sleep(3) # 等待冷启动与LSP预热

            self._servers[cwd] = {
                "process": process, "port": port, "last_accessed": time.time()
            }
            return port

    async def _evict_oldest_server(self):
        oldest_cwd = min(self._servers.keys(), key=lambda k: self._servers[k]["last_accessed"])
        logging.info(f"♻️ [LRU Pool] 达到并发上限，回收闲置沙盒: {oldest_cwd}")
        server_info = self._servers.pop(oldest_cwd)
        process = server_info["process"]
        try:
            process.terminate()
            await asyncio.wait_for(process.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            process.kill()
        except Exception:
            pass

    async def shutdown_all(self):
        logging.info(f"🛑 [ServerManager] 关闭所有沙盒 Server...")
        for cwd, server_info in self._servers.items():
            try:
                server_info["process"].terminate()
            except Exception:
                pass
        self._servers.clear()
