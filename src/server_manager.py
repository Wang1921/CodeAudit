import asyncio
import socket
import logging
import time
import sys
import aiohttp
from typing import Dict, Any, Optional, List

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

        # cwd -> {
        #     "process": Process,
        #     "port":": int,
        #     "stderr_task": asyncio.Task,
        #     "last_accessed": float,
        #     "idle_since": Optional[float]  # 首次检测到所有session空闲的时间戳
        # }
        self._servers: Dict[str, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()
        self._http_session: Optional[aiohttp.ClientSession] = None
        self._idle_timeout = 60.0  # 服务器空闲超过60秒才允许回收

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
        """
        回收最旧的服务器（传统LRU策略）
        注意：此方法仍保留用于向后兼容，但现在会先检查服务器是否空闲
        """
        # 找到最旧的服务器
        oldest_cwd = min(self._servers.keys(), key=lambda k: self._servers[k]["last_accessed"])
        logging.info(f"♻️ [LRU Pool] 达到并发上限，回收闲置沙盒: {oldest_cwd}")
        await self._cleanup_server(oldest_cwd)
    
    async def _fetch_session_statuses(self, port: int) -> Dict[str, Dict]:
        """
        获取指定端口的所有session状态（通过 /session/status 接口）
        
        Args:
            port: OpenCode服务器端口
        
        Returns:
            Dict[str, Dict]: 所有session的状态映射
                              例如：{"session1": {"type": "idle"}, "session2": {"type": "busy"}}
        
        Returns:
            空字典表示请求失败或无session
        """
        url = f"http://{self.hostname}:{port}/session/status"
        
        try:
            if not self._http_session or self._http_session.closed:
                self._http_session = aiohttp.ClientSession()
            
            async with self._http_session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    logging.debug(f"[Session监控] Port {port} 有 {len(data)} 个session")
                    return data
        except Exception as e:
            logging.debug(f"[Session监控] 获取session状态失败 (port={port}): {e}")
        
        return {}
    
    async def check_idle_servers(self) -> List[str]:
        """
        检查所有服务器的session状态，返回可以安全回收的服务器目录列表
        
        判断逻辑：
        1. 进程已退出 → 立即标记为可回收
        2. 通过 /session/status 检查所有session状态
        3. 所有session都是 idle 状态 → 记录空闲时间
        4. 空闲时间超过 self._idle_timeout (60秒) → 标记为可回收
        5. 有session处于 busy 状态 → 清除空闲计时，继续使用
        
        Returns:
            List[str]: 可以安全回收的服务器cwd列表
        """
        idle_servers = []
        current_time = time.time()
        
        for cwd, server_info in self._servers.items():
            try:
                # 1. 检查进程是否存活
                process = server_info["process"]
                if process.returncode is not None:
                    logging.warning(f"[Server监控] 进程已退出: {cwd} (returncode={process.returncode})")
                    idle_servers.append(cwd)
                    continue
                
                # 2. 通过 /session/status 检查所有session状态
                port = server_info["port"]
                statuses = await self._fetch_session_statuses(port)
                
                # 3. 判断是否所有session都是空闲状态
                if not statuses:
                    # 没有session，视为空闲
                    logging.debug(f"[Server监控] {cwd} (port={port}) 无活跃session")
                    all_idle = True
                else:
                    all_idle = all(
                        status.get("type") == "idle" 
                        for status in statuses.values()
                    )
                    
                    # 记录调试信息
                    busy_count = sum(1 for s in statuses.values() if s.get("type") != "idle")
                    if busy_count > 0:
                        logging.debug(f"[Server监控] {cwd} (port={port}) 有 {busy_count}/{len(statuses)} 个session忙碌")
                
                if all_idle:
                    # 所有session都空闲（或无session）
                    idle_since = server_info.get("idle_since")
                    
                    if idle_since is None:
                        # 首部检测到空闲，记录时间
                        server_info["idle_since"] = current_time
                        logging.info(f"[Server监控] {cwd} 检测到空闲状态，开始计时")
                    elif (current_time - idle_since) > self._idle_timeout:
                        # 空闲超过60秒，标记为可回收
                        idle_duration = current_time - idle_since
                        logging.info(f"[Server监控] {cwd} 空闲 {idle_duration:.1f}秒，可回收")
                        idle_servers.append(cwd)
                else:
                    # 有session在忙碌，清除空闲计时
                    if server_info.get("idle_since") is not None:
                        logging.info(f"[Server监控] {cwd} 重新进入忙碌状态，清除空闲计时")
                        server_info["idle_since"] = None
                    
            except Exception as e:
                logging.error(f"[Server监控] 检查服务器状态失败 {cwd}: {e}")
        
        return idle_servers
    
    async def evict_idle_servers(self, force: bool = False) -> int:
        """
        回收空闲服务器（智能回收策略）
        
        Args:
            force: 是否强制回收（即使未达上限），用于无任务时主动清理
        
        调用时机：
        - 达到 max_active_servers 上限时（force=False）
        - 主循环检测到无任务时（force=True，强制回收）
        
        回收策略：
        1. 调用 check_idle_servers() 获取可回收服务器列表
        2. 如果 force=True 或 达到上限，则回收
        3. 每次只回收一个（避免过度回收）
        
        Returns:
            int: 回收的服务器数量（0或1）
        """
        idle_servers = await self.check_idle_servers()
        
        # 改进：支持强制回收模式
        # - force=True: 无任务时主动清理
        # - force=False: 只在达到上限时回收
        should_evict = force or (len(self._servers) >= self.max_active_servers and idle_servers)
        
        if should_evict and idle_servers:
            # 达到上限或强制回收，且有可回收的服务器
            # 按空闲时间排序，回收空闲最久的
            idle_servers.sort(key=lambda cwd: self._servers[cwd].get("idle_since", 0))
            
            # 只回收一个服务器
            to_evict = idle_servers[0:1]
            for cwd in to_evict:
                idle_duration = time.time() - self._servers[cwd].get("idle_since", 0)
                if force:
                    logging.info(f"♻️ [ServerPool] 强制回收空闲服务器: {cwd} (空闲 {idle_duration:.1f}s)")
                else:
                    logging.info(f"♻️ [ServerPool] 达到上限，回收空闲服务器: {cwd} (空闲 {idle_duration:.1f}s)")
                await self._cleanup_server(cwd)
            
            return len(to_evict)
        
        return 0

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
