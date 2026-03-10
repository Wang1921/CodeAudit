import asyncio
import socket
import logging
import time
import sys
import aiohttp
from typing import Dict, Any, Optional

class OpenCodeServerManager:
    def __init__(
        self,
        max_active_servers: int = 5,
        hostname: str = "127.0.0.1",
        cors_origins: Optional[list] = None,
        auth_password: Optional[str] = None,
        health_check_timeout: float = 30.0,
        health_check_interval: float = 0.5
    ):
        self.max_active_servers = max_active_servers
        self.hostname = hostname
        self.cors_origins = cors_origins or []
        self.auth_password = auth_password
        self.health_check_timeout = health_check_timeout
        self.health_check_interval = health_check_interval

        # cwd -> {"process": Process, "port": int, "stderr_task": asyncio.Task, "last_accessed": float}
        self._servers: Dict[str, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()
        self._http_session: Optional[aiohttp.ClientSession] = None

    def _get_free_port(self) -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            return s.getsockname()[1]

    async def _read_stderr(self, process: asyncio.subprocess.Process, cwd: str):
        """后台读取 stderr 避免缓冲区填满"""
        try:
            while True:
                line = await process.stderr.readline()
                if not line:
                    break
                # 可选：记录 stderr 日志
                # logging.debug(f"[opencode stderr {cwd}]: {line.decode().strip()}")
        except Exception as e:
            logging.debug(f"stderr reader stopped for {cwd}: {e}")
        finally:
            if process.stderr and not process.stderr.at_eof():
                process.stderr.feed_eof()

    async def _check_server_health(self, port: int) -> bool:
        """检查 /global/health 端点确认服务器可用"""
        url = f"http://{self.hostname}:{port}/global/health"
        auth = None
        if self.auth_password:
            auth = aiohttp.BasicAuth("opencode", self.auth_password)

        deadline = time.time() + self.health_check_timeout
        while time.time() < deadline:
            try:
                if not self._http_session or self._http_session.closed:
                    self._http_session = aiohttp.ClientSession()

                async with self._http_session.get(url, auth=auth, timeout=2.0) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get("healthy"):
                            return True
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass
            await asyncio.sleep(self.health_check_interval)
        return False

    async def get_or_start_server(self, cwd: str) -> int:
        async with self._lock:
            # 检查现有服务器是否存活
            if cwd in self._servers:
                server_info = self._servers[cwd]
                process = server_info["process"]

                # 验证进程是否仍在运行
                if process.returncode is None:
                    # 可选：再次进行健康检查
                    if await self._check_server_health(server_info["port"]):
                        server_info["last_accessed"] = time.time()
                        return server_info["port"]
                    else:
                        # 健康检查失败，清理
                        logging.warning(f"⚠️ 服务器健康检查失败，重新启动: {cwd}")
                        await self._cleanup_server(cwd)

            # 达到上限时回收最旧的服务器
            if len(self._servers) >= self.max_active_servers:
                await self._evict_oldest_server()

            port = self._get_free_port()
            cmd = ["opencode", "serve", "--port", str(port), "--hostname", self.hostname]

            # 添加 CORS 配置
            for origin in self.cors_origins:
                cmd.extend(["--cors", origin])

            if sys.platform == "win32":
                cmd[0] = "opencode.exe"

            logging.info(f"🚀 [LRU Pool] 启动常驻沙盒 Server: {cwd} (端口: {port})")

            # 启动进程，将 stderr 重定向到后台任务读取
            process = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=cwd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE
            )

            # 启动后台任务读取 stderr 避免缓冲区填满
            stderr_task = asyncio.create_task(self._read_stderr(process, cwd))

            # 健康检查
            if not await self._check_server_health(port):
                # 启动失败，清理进程
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), timeout=2.0)
                except asyncio.TimeoutError:
                    process.kill()
                stderr_task.cancel()
                try:
                    await stderr_task
                except asyncio.CancelledError:
                    pass
                raise RuntimeError(f"服务器启动失败或健康检查超时: {cwd}")

            self._servers[cwd] = {
                "process": process,
                "port": port,
                "stderr_task": stderr_task,
                "last_accessed": time.time()
            }
            return port

    async def _cleanup_server(self, cwd: str):
        """清理指定 cwd 的服务器资源"""
        if cwd not in self._servers:
            return

        server_info = self._servers.pop(cwd)
        process = server_info["process"]
        stderr_task = server_info.get("stderr_task")

        # 取消 stderr 读取任务
        if stderr_task and not stderr_task.done():
            stderr_task.cancel()
            try:
                await stderr_task
            except asyncio.CancelledError:
                pass

        # 终止进程
        try:
            process.terminate()
            await asyncio.wait_for(process.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            process.kill()
        except Exception:
            pass

    async def _evict_oldest_server(self):
        oldest_cwd = min(self._servers.keys(), key=lambda k: self._servers[k]["last_accessed"])
        logging.info(f"♻️ [LRU Pool] 达到并发上限，回收闲置沙盒: {oldest_cwd}")
        await self._cleanup_server(oldest_cwd)

    async def shutdown_all(self):
        logging.info(f"🛑 [ServerManager] 关闭所有沙盒 Server...")
        tasks = []
        for cwd in list(self._servers.keys()):
            tasks.append(self._cleanup_server(cwd))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        # 关闭 HTTP 会话
        if self._http_session and not self._http_session.closed:
            await self._http_session.close()
