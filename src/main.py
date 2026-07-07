import argparse
import asyncio
import logging
import os
import sys

from src.agent_factory import OpenCodeConfig, list_available_backends, validate_backend
from src.engine import AuditEngine


def setup_logging():
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )

async def main():
    setup_logging()

    parser = argparse.ArgumentParser(description="多智能体代码审计系统")
    parser.add_argument("target_dir", help="待审计源代码的根目录")
    parser.add_argument(
        "--semgrep-rules",
        default=None,
        help="Semgrep 规则路径，支持多个（逗号分隔）：例如 '/path/to/vuln_rules,/path/to/api_routes'，默认使用内置规则目录",
    )
    parser.add_argument(
        "--agent-backend",
        choices=["claude", "opencode"],
        default="claude",
        help="LLM Agent 后端：claude (Claude Agent SDK 调本地 Claude Code CLI) 或 opencode (OpenCode HTTP server 子进程池)。默认 claude",
    )
    # OpenCode 后端专属参数
    parser.add_argument(
        "--opencode-model",
        default="volcengine/glm-5.2",
        help="OpenCode 后端的模型标识，格式 providerID/modelID。默认 volcengine/glm-5.2",
    )
    parser.add_argument(
        "--opencode-host",
        default="127.0.0.1",
        help="OpenCode server 监听地址。默认 127.0.0.1",
    )
    parser.add_argument(
        "--opencode-port-start",
        type=int,
        default=4096,
        help="OpenCode server 端口分配起始值（每个微服务占一个端口递增）。默认 4096",
    )
    parser.add_argument(
        "--opencode-timeout",
        type=float,
        default=300.0,
        help="OpenCode Agent 单次请求默认超时（秒）。默认 300",
    )
    args = parser.parse_args()

    # 校验后端依赖
    available = list_available_backends()
    logging.info(f"当前环境可用后端: {available}")
    ok, reason = validate_backend(args.agent_backend)
    if not ok:
        logging.error(f"后端 {args.agent_backend!r} 不可用: {reason}")
        sys.exit(1)
    logging.info(f"使用后端: {args.agent_backend} ({reason})")

    target_dir = os.path.abspath(args.target_dir)
    if not os.path.isdir(target_dir):
        logging.error(f"目标目录 {target_dir} 不存在。")
        sys.exit(1)

    import shutil

    # 清理旧的 .a2a_bus 目录
    a2a_bus_dir = os.path.join(target_dir, ".a2a_bus")
    if os.path.exists(a2a_bus_dir):
        try:
            shutil.rmtree(a2a_bus_dir)
            logging.info(f"已清理旧的审计状态: {a2a_bus_dir}")
        except Exception as e:
            logging.warning(f"清理 .a2a_bus 目录失败: {e}")

    # 清理旧的 .a2a_logs 目录
    a2a_logs_dir = os.path.join(target_dir, ".a2a_logs")
    if os.path.exists(a2a_logs_dir):
        try:
            shutil.rmtree(a2a_logs_dir)
            logging.info(f"已清理旧的日志目录: {a2a_logs_dir}")
        except Exception as e:
            logging.warning(f"清理 .a2a_logs 目录失败: {e}")

    # 清理旧的 reports 目录
    reports_dir = os.path.join(target_dir, "reports")
    if os.path.exists(reports_dir):
        try:
            shutil.rmtree(reports_dir)
            logging.info(f"已清理旧的漏洞报告: {reports_dir}")
        except Exception as e:
            logging.warning(f"清理 reports 目录失败: {e}")

    logging.info(f"正在初始化项目代码审计引擎: {target_dir}")

    # 按后端组装配置
    opencode_config = None
    if args.agent_backend == "opencode":
        opencode_config = OpenCodeConfig(
            model=args.opencode_model,
            hostname=args.opencode_host,
            port_start=args.opencode_port_start,
            default_timeout=args.opencode_timeout,
        )

    engine = AuditEngine(
        target_dir,
        semgrep_rules=args.semgrep_rules,
        backend=args.agent_backend,
        opencode_config=opencode_config,
    )

    try:
        await engine.run()
    except KeyboardInterrupt:
        logging.info("代码审计引擎正在关闭...")

def main_cli():
    """安装后由 `codeaudit` 命令调用（pyproject.toml 的 entry point）。"""
    asyncio.run(main())


if __name__ == "__main__":
    main_cli()
