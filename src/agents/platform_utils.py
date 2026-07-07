"""跨平台工具层。

集中处理 Windows / Linux 在子进程命令构造、可执行文件查找、路径格式上的差异。
两个 Agent 后端（Claude Agent SDK / OpenCode）共用本模块，避免平台分支逻辑碎片化。

设计原则：
- 所有 platform.system() 判断收口到本模块
- 返回值都是可直接喂给 asyncio.create_subprocess_exec / subprocess.run 的标准结构
- 配置文件内的路径统一用正斜杠（POSIX 风格），避免 JSON 转义问题
"""
import json
import logging
import os
import platform
import shutil
from typing import Any

logger = logging.getLogger(__name__)

IS_WINDOWS: bool = platform.system() == "Windows"
IS_LINUX: bool = platform.system() == "Linux"


def build_codegraph_mcp_command() -> list[str]:
    """构建 codegraph MCP server 的启动命令 token 数组。

    返回值是一个扁平的 argv 列表，适用于：
    - OpenCode 的 .opencode/opencode.json 里 mcp.<name>.command 字段
    - asyncio.create_subprocess_exec 的 *args

    Windows: ["cmd", "/c", "codegraph", "serve", "--mcp"]
    Linux:   ["codegraph", "serve", "--mcp"]

    若 codegraph 未安装（shutil.which 返回 None），仍返回标准命令，
    由调用方在启动时决定是否跳过 MCP 挂载（见 is_codegraph_available）。
    """
    if IS_WINDOWS:
        return ["cmd", "/c", "codegraph", "serve", "--mcp"]
    return ["codegraph", "serve", "--mcp"]


def build_codegraph_mcp_config_for_claude_sdk() -> dict[str, Any]:
    """构建 claude-agent-sdk 的 mcp_servers 配置条目。

    claude-agent-sdk 的 mcp_servers 接受 {"command": str, "args": list[str]} 结构，
    与 OpenCode 的扁平 command 数组不同，所以单独提供一个适配函数。
    """
    if IS_WINDOWS:
        return {"command": "cmd", "args": ["/c", "codegraph", "serve", "--mcp"]}
    return {"command": "codegraph", "args": ["serve", "--mcp"]}


def build_codegraph_init_args() -> list[str]:
    """构建 codegraph init -i 的命令 token 数组，供 asyncio.create_subprocess_exec 用。

    Windows: ["cmd", "/c", "codegraph", "init", "-i"]
    Linux:   ["codegraph", "init", "-i"]
    """
    if IS_WINDOWS:
        return ["cmd", "/c", "codegraph", "init", "-i"]
    return ["codegraph", "init", "-i"]


def is_codegraph_available() -> bool:
    """检测 codegraph 可执行文件是否在 PATH 中可用。

    两个后端都用这个函数决定是否挂载 codegraph MCP —— 当前环境未安装时
    跳过挂载，避免子进程启动失败。
    """
    found = shutil.which("codegraph")
    if found is None:
        # 也允许通过环境变量指定绝对路径
        env_bin = os.environ.get("CODEGRAPH_BIN")
        if env_bin and os.path.isfile(env_bin):
            return True
        return False
    return True


def resolve_codegraph_executable() -> str | None:
    """解析 codegraph 可执行文件路径。

    优先级：CODEGRAPH_BIN 环境变量 > shutil.which > None。
    """
    env_bin = os.environ.get("CODEGRAPH_BIN")
    if env_bin and os.path.isfile(env_bin):
        return env_bin
    return shutil.which("codegraph")


def resolve_opencode_executable() -> str | None:
    """解析 opencode 可执行文件路径。

    优先级：OPENCODE_BIN 环境变量 > shutil.which > None。

    注意：Windows 上 npm 全局安装通常产出 opencode.CMD / opencode.ps1，
    shutil.which 会返回 .CMD 路径。这种 .cmd 脚本不能被
    asyncio.create_subprocess_exec 直接执行，必须经 cmd /c 包装
    （见 build_opencode_serve_args）。
    """
    env_bin = os.environ.get("OPENCODE_BIN")
    if env_bin and os.path.isfile(env_bin):
        return env_bin
    return shutil.which("opencode")


def build_opencode_serve_args(
    port: int,
    hostname: str = "127.0.0.1",
    extra_args: list[str] | None = None,
) -> list[str]:
    """构建 opencode serve 启动命令的 token 数组。

    供 asyncio.create_subprocess_exec 使用。

    Windows 上若解析到 .cmd / .bat / .ps1 脚本，create_subprocess_exec
    无法直接执行（NotImplementedError），必须用 ["cmd", "/c", <exe>, ...] 包装。
    .exe 可直接执行。

    Args:
        port: 监听端口
        hostname: 监听地址，默认 127.0.0.1
        extra_args: 额外命令行参数（如 --cors）

    Returns:
        argv 列表

    Raises:
        RuntimeError: opencode 未安装
    """
    exe = resolve_opencode_executable()
    if exe is None:
        raise RuntimeError(
            "opencode 可执行文件未找到，请确认已安装 opencode-ai 或设置 OPENCODE_BIN 环境变量"
        )

    base_args = ["serve", "--port", str(port), "--hostname", hostname]
    if extra_args:
        base_args.extend(extra_args)

    lower_exe = exe.lower()
    if IS_WINDOWS and (lower_exe.endswith(".cmd") or lower_exe.endswith(".bat")):
        # .cmd / .bat 脚本必须经 cmd /c 执行
        return ["cmd", "/c", exe] + base_args
    if IS_WINDOWS and lower_exe.endswith(".ps1"):
        # .ps1 经 powershell 执行
        return ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", exe] + base_args
    return [exe] + base_args


def to_posix_path(p: str) -> str:
    """将路径转为正斜杠形式。

    用于写入 JSON 配置文件（如 .opencode/opencode.json 的 mcp.command 里的路径），
    避免 Windows 反斜杠在 JSON 里需要转义的问题。
    """
    return p.replace("\\", "/")


def build_opencode_mcp_config(
    server_name: str,
    command_tokens: list[str],
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    """构建 OpenCode 的 mcp 配置条目（写入 .opencode/opencode.json 的 mcp 段）。

    OpenCode 的 mcp 配置格式：
        {
          "type": "local",
          "command": ["cmd", "/c", "codegraph", "serve", "--mcp"],
          "env": {"KEY": "VALUE"}   # 可选
        }

    Args:
        server_name: MCP server 名称，如 "codegraph"
        command_tokens: 启动命令 token 数组（来自 build_codegraph_mcp_command 等）
        env: 可选环境变量

    Returns:
        {server_name: {config dict}} 结构，可直接 merge 进 mcp 段
    """
    cfg: dict[str, Any] = {
        "type": "local",
        "command": list(command_tokens),
    }
    if env:
        cfg["env"] = dict(env)
    return {server_name: cfg}


def write_opencode_project_config(
    cwd: str,
    mcp_servers: dict[str, Any] | None = None,
    extra_config: dict[str, Any] | None = None,
) -> str | None:
    """在指定目录写入项目级 .opencode/opencode.json 配置文件。

    若目录下已有 .opencode/opencode.json，会读取后 merge，不覆盖用户既有配置。

    Args:
        cwd: 目标项目目录
        mcp_servers: MCP server 配置字典，形如 {"codegraph": {...}}
        extra_config: 额外的顶层配置字段

    Returns:
        写入的配置文件路径；若写入失败返回 None
    """
    config_dir = os.path.join(cwd, ".opencode")
    config_path = os.path.join(config_dir, "opencode.json")

    try:
        os.makedirs(config_dir, exist_ok=True)

        # 读取既有配置（merge 模式，不覆盖用户配置）
        existing: dict[str, Any] = {}
        if os.path.exists(config_path):
            with open(config_path, encoding="utf-8") as f:
                try:
                    existing = json.load(f) or {}
                except json.JSONDecodeError:
                    logger.warning(f"既有 opencode.json 解析失败，将覆盖: {config_path}")
                    existing = {}

        # merge mcp 段
        if mcp_servers:
            existing_mcp = existing.get("mcp", {})
            existing_mcp.update(mcp_servers)
            existing["mcp"] = existing_mcp

        if extra_config:
            existing.update(extra_config)

        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2, ensure_ascii=False)

        logger.debug(f"已写入 opencode 项目配置: {config_path}")
        return config_path
    except Exception as e:
        logger.warning(f"写入 opencode 项目配置失败 {config_path}: {e}")
        return None


def cleanup_opencode_project_config(cwd: str, mcp_names: list[str] | None = None) -> None:
    """清理引擎写入的 opencode 项目配置。

    为避免污染用户项目，引擎退出时应调用本函数移除自己注入的 MCP server 条目。
    若 mcp 段被清空则删除整个 mcp 段；若整个配置文件只剩空结构则删除文件。

    Args:
        cwd: 目标项目目录
        mcp_names: 引擎注入的 MCP server 名称列表，None 表示清空所有 mcp 段
    """
    config_path = os.path.join(cwd, ".opencode", "opencode.json")
    if not os.path.exists(config_path):
        return

    try:
        with open(config_path, encoding="utf-8") as f:
            config = json.load(f)
        if not isinstance(config, dict):
            return

        mcp = config.get("mcp", {})
        if mcp_names is None:
            mcp = {}
        else:
            for name in mcp_names:
                mcp.pop(name, None)

        if mcp:
            config["mcp"] = mcp
        else:
            config.pop("mcp", None)

        if config:
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
        else:
            os.remove(config_path)
            # 若 .opencode 目录也空了，一并清理
            config_dir = os.path.join(cwd, ".opencode")
            if os.path.isdir(config_dir) and not os.listdir(config_dir):
                os.rmdir(config_dir)
    except Exception as e:
        logger.debug(f"清理 opencode 项目配置失败 {config_path}: {e}")


def find_free_port(start: int = 4096, end: int = 65535) -> int:
    """在 [start, end] 范围内找一个可绑定端口。

    用于给 opencode serve 分配监听端口。绑 0 让 OS 分配更简单，
    但 opencode serve 的 --port 0 行为不确定（可能打印到 stdout），
    所以这里主动找一个可用端口，便于调用方提前知道端口号。

    Returns:
        可用端口号

    Raises:
        OSError: 范围内无可用端口
    """
    import socket

    for port in range(start, end + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(("127.0.0.1", port))
            sock.close()
            return port
        except OSError:
            continue
    raise OSError(f"在 [{start}, {end}] 范围内未找到可用端口")
