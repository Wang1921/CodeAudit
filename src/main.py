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
    
    parser = argparse.ArgumentParser(description="Multi-Agent Code Auditing System")
    parser.add_argument("target_dir", help="The root directory of the source code to audit")
    args = parser.parse_args()

    target_dir = os.path.abspath(args.target_dir)
    if not os.path.isdir(target_dir):
        logging.error(f"Target directory {target_dir} does not exist.")
        sys.exit(1)

    logging.info(f"Initializing Audit Engine for project: {target_dir}")
    engine = AuditEngine(target_dir)
    
    try:
        await engine.run()
    except KeyboardInterrupt:
        logging.info("Audit Engine shutting down...")

if __name__ == "__main__":
    asyncio.run(main())
