"""OpenCode server 子进程池管理器。

按 doc/HTTP沙盒池设计文档.md V2.0 实现，每个 cwd 对应一个独立的
`opencode serve` 子进程，通过 LRU + 空闲监控双重策略回收。

三阶段锁设计（避免冷启动串行化）：
- Phase 1: 短持 _dict_lock 查字典，命中则更新 last_accessed 后释放锁
- Phase 2: 锁外做健康检查（GET /global/health）
- Phase 3: per-cwd _startup_locks[cwd] 独占冷启动，双重检查后启动子进程

跨平台处理：
- opencode.CMD / .ps1 脚本必须经 cmd /c 或 powershell 包装（见 platform_utils）
- codegraph MCP 通过 .opencode/opencode.json 配置文件注入（机制 A）
- 子进程 terminate→wait→kill 三段式在 Windows/Linux 都安全
"""
import asyncio
import json
import logging
import os
import time
from typing import Any

import aiohttp

from src.agents.platform_utils import (
    IS_WINDOWS,
    build_codegraph_mcp_command,
    build_opencode_mcp_config,
    build_opencode_serve_args,
    cleanup_opencode_project_config,
    is_codegraph_available,
    write_opencode_project_config,
)

logger = logging.getLogger(__name__)


class _ServerInfo:
    """单个 opencode server 进程的运行时信息。"""

    __slots__ = (
        "cwd", "port", "process", "stderr_task",
        "last_accessed", "idle_since", "healthy",
    )

    def __init__(self, cwd: str, port: int, process: asyncio.subprocess.Process,
                 stderr_task: asyncio.Task):
        self.cwd = cwd
        self.port = port
        self.process = process
        self.stderr_task = stderr_task
        self.last_accessed = time.time()
        self.idle_since: float | None = None
        self.healthy = True


class OpenCodeServerManager:
    """管理多个 opencode serve 子进程。

    生命周期：
    - get_or_start_server(cwd) -> port：获取或启动 server，返回端口
    - check_idle_servers() -> list[cwd]：扫描所有 server 的 session 状态，返回可回收列表
    - evict_idle_servers(force) -> int：回收空闲 server
    - shutdown_all()：关闭所有 server
    """

    def __init__(
        self,
        max_active_servers: int = 5,
        hostname: str = "127.0.0.1",
        health_check_timeout: float = 30.0,
        health_check_interval: float = 0.5,
        idle_timeout: float = 60.0,
        port_start: int = 4096,
    ):
        self.max_active_servers = max_active_servers
        self.hostname = hostname
        self.health_check_timeout = health_check_timeout
        self.health_check_interval = health_check_interval
        self._idle_timeout = idle_timeout
        self.port_start = port_start

        # cwd -> _ServerInfo
        self._servers: dict[str, _ServerInfo] = {}
        # 字典锁（只护 _servers / _last_active 字典读写）
        self._dict_lock = asyncio.Lock()
        # per-cwd 启动锁（护单个 cwd 的冷启动，不同 cwd 不互斥）
        self._startup_locks: dict[str, asyncio.Lock] = {}
        # 引擎注入的 MCP server 名称清单，用于退出时清理配置文件
        self._injected_mcp_names = ["codegraph"] if is_codegraph_available() else []

    def _get_startup_lock(self, cwd: str) -> asyncio.Lock:
        """获取（或延迟创建）cwd 对应的启动锁。调用方须持 _dict_lock。"""
        if cwd not in self._startup_locks:
            self._startup_locks[cwd] = asyncio.Lock()
        return self._startup_locks[cwd]

    async def get_or_start_server(self, cwd: str) -> int:
        """获取或启动 cwd 对应的 opencode server，返回监听端口。

        三阶段设计，最大化并发吞吐：
        - Phase 1: 短持 _dict_lock 查字典
        - Phase 2: 锁外健康检查
        - Phase 3: per-cwd 启动锁内冷启动
        """
        # Phase 1: 快路径
        async with self._dict_lock:
            info = self._servers.get(cwd)
            if info is not None:
                info.last_accessed = time.time()
                port = info.port
            else:
                port = None

        if port is not None:
            # Phase 2: 锁外健康检查
            if await self._check_server_health(port):
                return port
            # 不健康，清理后降级到 Phase 3 重启
            async with self._dict_lock:
                bad = self._servers.pop(cwd, None)
            if bad is not None:
                await self._dispose_server_info(bad)
            logger.warning(f"server 不健康已清理，cwd={cwd}，准备重启")

        # Phase 3: 慢路径（per-cwd 启动锁）
        async with self._dict_lock:
            startup_lock = self._get_startup_lock(cwd)

        async with startup_lock:
            # 双重检查：可能另一协程刚启动成功
            async with self._dict_lock:
                info = self._servers.get(cwd)
                if info is not None:
                    info.last_accessed = time.time()
                    return info.port
                # 容量满则驱逐最旧
                if len(self._servers) >= self.max_active_servers:
                    evicted = await self._evict_oldest_locked()
                    if evicted is not None:
                        await self._dispose_server_info(evicted)

            # 锁外启动子进程（耗时操作不持 _dict_lock）
            info = await self._start_server(cwd)

            async with self._dict_lock:
                # 再次双重检查
                existing = self._servers.get(cwd)
                if existing is not None:
                    # 并发竞争，另一协程先成功，丢弃本次启动
                    await self._dispose_server_info(info)
                    return existing.port
                self._servers[cwd] = info

            return info.port

    async def _start_server(self, cwd: str) -> _ServerInfo:
        """启动一个 opencode serve 子进程。调用方须持有 per-cwd 启动锁。"""
        # 1. 写入项目级 .opencode/opencode.json，注入 codegraph MCP
        self._write_mcp_config(cwd)

        # 2. 找一个可用端口
        from src.agents.platform_utils import find_free_port

        port = find_free_port(start=self.port_start)
        # 3. 构建启动命令
        args = build_opencode_serve_args(port=port, hostname=self.hostname)

        logger.info(f"启动 opencode serve: cwd={cwd}, port={port}, cmd={' '.join(args)}")

        # 4. 启动子进程
        process = await asyncio.create_subprocess_exec(
            *args,
            cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # 5. 启动 stderr reader 任务（持续读取避免管道阻塞）
        stderr_task = asyncio.create_task(self._read_stderr(process, cwd))

        # 6. 健康检查轮询
        try:
            await self._wait_for_health(port)
        except Exception:
            # 健康检查失败，清理进程
            stderr_task.cancel()
            try:
                process.terminate()
                await asyncio.wait_for(process.wait(), timeout=2.0)
            except (asyncio.TimeoutError, ProcessLookupError):
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
            raise RuntimeError(f"opencode server 启动失败或健康检查超时: cwd={cwd}")

        logger.info(f"opencode server 已就绪: cwd={cwd}, port={port}")
        return _ServerInfo(cwd=cwd, port=port, process=process, stderr_task=stderr_task)

    def _write_mcp_config(self, cwd: str) -> None:
        """写入 .opencode/opencode.json，注入 codegraph MCP（仅当可用）。"""
        if not is_codegraph_available():
            return
        mcp_config = build_opencode_mcp_config(
            server_name="codegraph",
            command_tokens=build_codegraph_mcp_command(),
        )
        write_opencode_project_config(cwd=cwd, mcp_servers=mcp_config)

    async def _read_stderr(self, process: asyncio.subprocess.Process, cwd: str):
        """持续读取子进程 stderr，避免管道缓冲阻塞导致子进程挂起。

        每行写入 debug 日志，便于排查 opencode serve 启动问题。
        """
        try:
            while True:
                line = await process.stderr.readline()
                if not line:
                    break
                text = line.decode(errors="replace").rstrip()
                if text:
                    logger.debug(f"[opencode:{cwd}] {text}")
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.debug(f"[opencode:{cwd}] stderr reader 异常: {e}")

    async def _wait_for_health(self, port: int) -> None:
        """轮询 /global/health 直到 healthy=True 或超时。"""
        deadline = time.time() + self.health_check_timeout
        url = f"http://{self.hostname}:{port}/global/health"

        async with aiohttp.ClientSession() as session:
            while time.time() < deadline:
                try:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=2.0)) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            if data.get("healthy") is True:
                                return
                except (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError):
                    pass
                await asyncio.sleep(self.health_check_interval)

        raise TimeoutError(f"健康检查超时: {url}")

    async def _check_server_health(self, port: int) -> bool:
        """单次健康检查（不轮询），用于快路径验证存量 server。"""
        url = f"http://{self.hostname}:{port}/global/health"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=3.0)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get("healthy") is True
        except (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError):
            return False
        return False

    async def _fetch_session_statuses(self, port: int) -> dict:
        """请求 /session/status 获取所有 session 状态。"""
        url = f"http://{self.hostname}:{port}/session/status"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5.0)) as resp:
                    if resp.status == 200:
                        return await resp.json()
        except (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError):
            pass
        return {}

    async def _evict_oldest_locked(self) -> _ServerInfo | None:
        """驱逐最久未使用的 server（调用方须持 _dict_lock）。

        选 last_accessed 最小的条目，从字典 pop 后返回，由调用方在锁外 dispose。
        """
        if not self._servers:
            return None
        oldest_cwd = min(self._servers, key=lambda c: self._servers[c].last_accessed)
        return self._servers.pop(oldest_cwd, None)

    async def _dispose_server_info(self, info: _ServerInfo) -> None:
        """释放单个 server 进程资源（不持任何锁，可并发调用）。

        三段式终止：cancel stderr_task → terminate → wait(2s) → kill。
        所有操作 try/except，异常只打 debug 日志，不抛出。
        """
        if info.stderr_task and not info.stderr_task.done():
            info.stderr_task.cancel()
            try:
                await info.stderr_task
            except (asyncio.CancelledError, Exception):
                pass

        if info.process.returncode is None:
            try:
                info.process.terminate()
                await asyncio.wait_for(info.process.wait(), timeout=2.0)
            except (asyncio.TimeoutError, ProcessLookupError):
                try:
                    info.process.kill()
                except ProcessLookupError:
                    pass
            except Exception as e:
                logger.debug(f"dispose 进程异常 cwd={info.cwd}: {e}")

        # 显式关闭子进程的 stdin/stdout/stderr pipe transport，
        # 避免 Windows ProactorEventLoop 的 ResourceWarning（unclosed transport）噪声。
        for pipe_name in ("stdin", "stdout", "stderr"):
            try:
                transport = getattr(info.process, pipe_name, None)
                if transport is not None and not transport.is_closing():
                    transport.close()
            except Exception:
                pass

        # 清理引擎注入的 MCP 配置文件
        try:
            cleanup_opencode_project_config(info.cwd, self._injected_mcp_names)
        except Exception:
            pass

    async def check_idle_servers(self) -> list[str]:
        """扫描所有 server 的 session 状态，返回可回收的 cwd 列表。

        判定条件：所有 session type==idle（或无 session）且持续超过 _idle_timeout。
        """
        async with self._dict_lock:
            snapshots = [(cwd, info) for cwd, info in self._servers.items()]

        reclaimable: list[str] = []
        now = time.time()
        for cwd, info in snapshots:
            statuses = await self._fetch_session_statuses(info.port)
            # statuses 是 {session_id: {type: ...}} 结构
            sessions = statuses if isinstance(statuses, dict) else {}
            all_idle = True
            for sess in sessions.values():
                if isinstance(sess, dict) and sess.get("type") != "idle":
                    all_idle = False
                    break

            async with self._dict_lock:
                current = self._servers.get(cwd)
                if current is None:
                    continue
                if all_idle:
                    if current.idle_since is None:
                        current.idle_since = now
                    elif now - current.idle_since > self._idle_timeout:
                        reclaimable.append(cwd)
                else:
                    current.idle_since = None

        return reclaimable

    async def evict_idle_servers(self, force: bool = False) -> int:
        """回收空闲 server。

        Args:
            force: True 时无条件回收最久空闲的一个；False 时仅在容量满时回收。

        Returns:
            实际回收数量
        """
        reclaimable: list[str] = []
        if force:
            # 找 idle_since 最早的一个
            async with self._dict_lock:
                idle_candidates = [
                    (cwd, info) for cwd, info in self._servers.items()
                    if info.idle_since is not None
                ]
            if idle_candidates:
                idle_candidates.sort(key=lambda x: x[1].idle_since)
                reclaimable = [idle_candidates[0][0]]
        else:
            reclaimable = await self.check_idle_servers()

        evicted = 0
        for cwd in reclaimable:
            async with self._dict_lock:
                info = self._servers.pop(cwd, None)
            if info is not None:
                await self._dispose_server_info(info)
                evicted += 1
                logger.info(f"回收空闲 server: cwd={cwd}")

        return evicted

    async def shutdown_all(self) -> None:
        """关闭所有 server。原子清字典后并发 dispose。"""
        async with self._dict_lock:
            infos = list(self._servers.values())
            self._servers.clear()

        if not infos:
            return

        logger.info(f"正在关闭 {len(infos)} 个 opencode server...")
        await asyncio.gather(*[self._dispose_server_info(i) for i in infos], return_exceptions=True)
        logger.info("所有 opencode server 已关闭")

    @property
    def active_count(self) -> int:
        return len(self._servers)

    def get_stats(self) -> dict[str, Any]:
        return {
            "active_count": len(self._servers),
            "max_active_servers": self.max_active_servers,
            "working_dirs": list(self._servers.keys()),
        }
