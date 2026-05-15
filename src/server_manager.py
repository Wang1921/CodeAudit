import asyncio
import logging
import socket
import sys
import time
from typing import Any

import aiohttp


class OpenCodeServerManager:
    def __init__(
        self,
        max_active_servers: int = 5,
        hostname: str = "127.0.0.1",
        cors_origins: list | None = None,
        auth_password: str | None = None,
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
        #     "port": int,
        #     "stderr_task": asyncio.Task,
        #     "last_accessed": float,
        #     "idle_since": Optional[float]
        # }
        self._servers: dict[str, dict[str, Any]] = {}
        # 细粒度锁策略：
        # - _dict_lock: 短期持有，只保护 _servers 字典的读写
        # - _startup_locks[cwd]: per-cwd 启动锁，串行化同目录的并发冷启动，
        #   但允许不同 cwd 并发启动，以及热路径上的 get 完全不阻塞彼此
        self._dict_lock = asyncio.Lock()
        self._startup_locks: dict[str, asyncio.Lock] = {}
        self._startup_locks_mutex = asyncio.Lock()

        self._http_session: aiohttp.ClientSession | None = None
        self._idle_timeout = 60.0  # 服务器空闲超过60秒才允许回收

    def _get_free_port(self) -> int:
        """问操作系统要一个当前空闲的临时端口。

        实现是 bind 到 port 0 让内核挑端口，然后立刻关闭 socket 把端口号让出去。
        注意：返回后到 OpenCode 真正 bind 之间存在极小 TOCTOU 窗口（理论上可被别人抢），
        实际撞车概率低，被抢时上层启动失败会自动重试。
        """
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
        except Exception as e:
            logging.debug(f"stderr reader stopped for {cwd}: {e}")
        finally:
            if process.stderr and not process.stderr.at_eof():
                process.stderr.feed_eof()

    async def _check_server_health(self, port: int) -> bool:
        """检查 /global/health 端点确认服务器可用（锁外调用）"""
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

    async def _get_startup_lock(self, cwd: str) -> asyncio.Lock:
        """延迟分配 per-cwd 启动锁。"""
        async with self._startup_locks_mutex:
            lock = self._startup_locks.get(cwd)
            if lock is None:
                lock = asyncio.Lock()
                self._startup_locks[cwd] = lock
            return lock

    async def _dispose_server_info(self, info: dict[str, Any], cwd: str) -> None:
        """仅做进程与 stderr 回收，不触碰字典。调用者必须先把 info 从字典 pop 出来。"""
        process = info["process"]
        stderr_task = info.get("stderr_task")

        if stderr_task and not stderr_task.done():
            stderr_task.cancel()
            try:
                await stderr_task
            except asyncio.CancelledError:
                pass
            except Exception as e:
                logging.debug(f"stderr_task 关闭异常 {cwd}: {e}")

        try:
            if process.returncode is None:
                process.terminate()
                await asyncio.wait_for(process.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            process.kill()
            try:
                await process.wait()
            except Exception:
                pass
        except Exception as e:
            logging.debug(f"dispose_server_info({cwd}) 失败: {e}")

    async def _evict_oldest_locked(self) -> tuple | None:
        """在已持有 _dict_lock 的前提下，pop 最旧的 server。返回 (cwd, info) 或 None。"""
        if not self._servers:
            return None
        oldest_cwd = min(self._servers.keys(), key=lambda k: self._servers[k]["last_accessed"])
        info = self._servers.pop(oldest_cwd)
        return oldest_cwd, info

    async def get_or_start_server(self, cwd: str) -> int:
        """获取 cwd 对应的 OpenCode server 端口。不存在则启动新的。

        锁策略：
        - 快路径（已存在 + 进程存活）：只短期持字典锁记录 last_accessed，
          健康检查放在锁外，这样 N 个协程查同一个健康 server 不再互相阻塞。
        - 慢路径（需要启动）：用 per-cwd 启动锁串行同目录并发，但不会阻塞其他 cwd。
        """
        # Phase 1: 快路径 —— 锁内只做字典查找
        port: int | None = None
        async with self._dict_lock:
            info = self._servers.get(cwd)
            if info is not None and info["process"].returncode is None:
                port = info["port"]
                info["last_accessed"] = time.time()

        # Phase 2: 锁外健康检查
        if port is not None:
            if await self._check_server_health(port):
                return port
            logging.warning(f"⚠️ 服务器健康检查失败，重新启动: {cwd}")
            # 健康检查失败：移出字典并回收（锁外 dispose 长操作）
            async with self._dict_lock:
                stale = self._servers.pop(cwd, None)
            if stale is not None:
                await self._dispose_server_info(stale, cwd)

        # Phase 3: 启动新 server，per-cwd 串行化同目录的并发启动
        startup_lock = await self._get_startup_lock(cwd)
        async with startup_lock:
            # 双重检查：可能另一个协程刚刚启动完成
            async with self._dict_lock:
                info = self._servers.get(cwd)
                if info is not None and info["process"].returncode is None:
                    info["last_accessed"] = time.time()
                    return info["port"]
                evicted = None
                if len(self._servers) >= self.max_active_servers:
                    evicted = await self._evict_oldest_locked()

            # 锁外：回收被淘汰的旧 server
            if evicted is not None:
                old_cwd, old_info = evicted
                logging.info(f"♻️ [LRU Pool] 达到并发上限，回收闲置沙盒: {old_cwd}")
                await self._dispose_server_info(old_info, old_cwd)

            # 锁外：启动新 subprocess + 健康检查
            port = self._get_free_port()
            cmd = ["opencode", "serve", "--port", str(port), "--hostname", self.hostname]
            for origin in self.cors_origins:
                cmd.extend(["--cors", origin])
            if sys.platform == "win32":
                cmd[0] = "opencode.exe"

            logging.info(f"🚀 [LRU Pool] 启动常驻沙盒 Server: {cwd} (端口: {port})")

            process = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=cwd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE
            )
            stderr_task = asyncio.create_task(self._read_stderr(process, cwd))

            if not await self._check_server_health(port):
                # 启动失败，回收进程再抛错
                try:
                    process.terminate()
                    await asyncio.wait_for(process.wait(), timeout=2.0)
                except asyncio.TimeoutError:
                    process.kill()
                except Exception:
                    pass
                stderr_task.cancel()
                try:
                    await stderr_task
                except asyncio.CancelledError:
                    pass
                raise RuntimeError(f"服务器启动失败或健康检查超时: {cwd}")

            # 注册到字典
            new_info = {
                "process": process,
                "port": port,
                "stderr_task": stderr_task,
                "last_accessed": time.time(),
            }
            async with self._dict_lock:
                self._servers[cwd] = new_info
            return port

    async def _cleanup_server(self, cwd: str):
        """清理指定 cwd 的服务器资源（保留公共 API，内部走新 dispose 路径）。"""
        async with self._dict_lock:
            info = self._servers.pop(cwd, None)
        if info is None:
            return
        await self._dispose_server_info(info, cwd)

    async def _fetch_session_statuses(self, port: int) -> dict[str, dict]:
        """获取指定端口的所有 session 状态（通过 /session/status 接口）。"""
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

    async def check_idle_servers(self) -> list[str]:
        """检查所有服务器的 session 状态，返回可以安全回收的服务器目录列表。

        判断逻辑：
        1. 进程已退出 → 立即标记为可回收
        2. 所有 session 都是 idle → 记录/累积空闲时间；超过 `_idle_timeout` 则可回收
        3. 有 session 忙碌 → 清除空闲计时
        """
        idle_servers: list[str] = []
        current_time = time.time()

        # 字典锁内做浅拷贝，随后遍历副本（锁外做 HTTP 探测）
        async with self._dict_lock:
            snapshot = list(self._servers.items())

        for cwd, server_info in snapshot:
            try:
                process = server_info["process"]
                if process.returncode is not None:
                    logging.warning(f"[Server监控] 进程已退出: {cwd} (returncode={process.returncode})")
                    idle_servers.append(cwd)
                    continue

                port = server_info["port"]
                statuses = await self._fetch_session_statuses(port)

                if not statuses:
                    all_idle = True
                else:
                    all_idle = all(s.get("type") == "idle" for s in statuses.values())
                    busy_count = sum(1 for s in statuses.values() if s.get("type") != "idle")
                    if busy_count > 0:
                        logging.debug(f"[Server监控] {cwd} (port={port}) 有 {busy_count}/{len(statuses)} 个session忙碌")

                if all_idle:
                    idle_since = server_info.get("idle_since")
                    if idle_since is None:
                        # 回写真字典（条目可能已被其他协程回收）
                        async with self._dict_lock:
                            live = self._servers.get(cwd)
                            if live is not None:
                                live["idle_since"] = current_time
                                logging.info(f"[Server监控] {cwd} 检测到空闲状态，开始计时")
                    elif (current_time - idle_since) > self._idle_timeout:
                        idle_duration = current_time - idle_since
                        logging.info(f"[Server监控] {cwd} 空闲 {idle_duration:.1f}秒，可回收")
                        idle_servers.append(cwd)
                else:
                    if server_info.get("idle_since") is not None:
                        async with self._dict_lock:
                            live = self._servers.get(cwd)
                            if live is not None:
                                live["idle_since"] = None
                                logging.info(f"[Server监控] {cwd} 重新进入忙碌状态，清除空闲计时")
            except Exception as e:
                logging.error(f"[Server监控] 检查服务器状态失败 {cwd}: {e}")

        return idle_servers

    async def evict_idle_servers(self, force: bool = False) -> int:
        """回收空闲服务器（智能回收策略）。

        策略：
        - force=True：无任务时主动清理
        - force=False：只在达到上限时回收
        - 每次只回收一个（避免过度回收）
        """
        idle_servers = await self.check_idle_servers()
        should_evict = force or (len(self._servers) >= self.max_active_servers and idle_servers)

        if not (should_evict and idle_servers):
            return 0

        # 锁内选出 idle 最久的 + 原子 pop
        async with self._dict_lock:
            candidates = [c for c in idle_servers if c in self._servers]
            candidates.sort(key=lambda c: self._servers[c].get("idle_since") or 0)
            if not candidates:
                return 0
            to_evict_cwd = candidates[0]
            info = self._servers.pop(to_evict_cwd)

        idle_duration = time.time() - (info.get("idle_since") or 0)
        if force:
            logging.info(f"♻️ [ServerPool] 强制回收空闲服务器: {to_evict_cwd} (空闲 {idle_duration:.1f}s)")
        else:
            logging.info(f"♻️ [ServerPool] 达到上限，回收空闲服务器: {to_evict_cwd} (空闲 {idle_duration:.1f}s)")

        # 锁外 dispose
        await self._dispose_server_info(info, to_evict_cwd)
        return 1

    async def shutdown_all(self):
        """引擎收尾：关闭沙盒池中所有 OpenCode server 子进程并关掉共享 aiohttp session。

        实现要点：先在锁内一次性原子清空 self._servers 字典（避免并发 get_or_start_server
        把刚 pop 出来的实例又塞回来），再在锁外并发 dispose 所有实例，避免逐个串行等待。
        """
        logging.info("🛑 [ServerManager] 关闭所有沙盒 Server...")
        # 原子清空字典，随后并发 dispose 所有 info
        async with self._dict_lock:
            items = list(self._servers.items())
            self._servers.clear()

        if items:
            await asyncio.gather(
                *(self._dispose_server_info(info, cwd) for cwd, info in items),
                return_exceptions=True,
            )

        if self._http_session and not self._http_session.closed:
            await self._http_session.close()
