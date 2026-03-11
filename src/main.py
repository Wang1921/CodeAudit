import asyncio
import logging
import argparse
import sys
import os

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
    args = parser.parse_args()

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
    reports_dir = "reports"
    if os.path.exists(reports_dir):
        try:
            shutil.rmtree(reports_dir)
            logging.info(f"已清理旧的漏洞报告: {reports_dir}")
        except Exception as e:
            logging.warning(f"清理 reports 目录失败: {e}")
    
    logging.info(f"正在初始化项目代码审计引擎: {target_dir}")
    engine = AuditEngine(target_dir, semgrep_rules=args.semgrep_rules)
    
    try:
        await engine.run()
    except KeyboardInterrupt:
        logging.info("代码审计引擎正在关闭...")

if __name__ == "__main__":
    asyncio.run(main())
