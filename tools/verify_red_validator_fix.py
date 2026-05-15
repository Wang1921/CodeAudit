"""小批量验证 RedValidator 修复（3 次重复跑）。

case: 用 v12 baseline 中被错判 NOT_EXPLOITABLE 的 Assignment5.java (/challenge/5)
完整 sink payload 重新调 RedValidator，看 3 次是否都判 EXPLOITABLE。

修复前：RedValidator 输出 {"status": "NOT_EXPLOITABLE"} 29 字符（漏报根因）
修复后预期：3 次都判 EXPLOITABLE 并产出 attack_vector / poc_payload；
           或若仍判 NOT_EXPLOITABLE，必须带 defense_analysis 字段证明（schema 强约束）
"""
import asyncio
import json
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import prompts
from src.agent import OpenCodeAgent
from src.server_manager import OpenCodeServerManager

logging.basicConfig(level=logging.WARNING, format="%(asctime)s [%(levelname)s] %(message)s")

TARGET_PROJECT = "/home/wzq/WebGoat"

# 这个 payload 复刻 v12 baseline ReverseTracer 输出（被 RedValidator 错判 NOT_EXPLOITABLE）
PAYLOAD = {
    "vuln_type": "SQL Injection",
    "entry_route": "/challenge/5",
    "filepath": "/home/wzq/WebGoat/src/main/java/org/owasp/webgoat/lessons/challenges/challenge5/Assignment5.java",
    "line_number": "44",
    "call_chain": [
        "1. login() - /challenge/5",
        "2. connection.prepareStatement()",
    ],
    "suspicion_reason": "login()方法直接将用户输入的username_login和password_login拼接到SQL查询字符串中，未对输入进行任何SQL注入防护处理，导致存在SQL注入漏洞",
    "cwe": ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command"],
}


async def run_one(server_manager: OpenCodeServerManager, attempt: int) -> dict:
    payload_json = json.dumps(PAYLOAD, ensure_ascii=False)
    prompt = prompts.format_red_validator_prompt(payload_json)
    output_schema = prompts.get_output_schema("RedValidator")
    port = await server_manager.get_or_start_server(TARGET_PROJECT)
    async with OpenCodeAgent(port=port, timeout=300) as agent:
        result = await agent.execute(
            prompt,
            allowed_tools="lsp,read,codesearch",
            output_schema=output_schema,
        )
    so = result.get("structured_output")
    response = result.get("response", "")
    if not isinstance(response, str):
        response = json.dumps(response, ensure_ascii=False)
    return {
        "attempt": attempt,
        "structured_output": so,
        "response_len": len(response),
    }


async def main() -> None:
    sm = OpenCodeServerManager(max_active_servers=2)
    summary = []
    try:
        for i in range(1, 4):
            print(f"\n{'=' * 90}\n第 {i}/3 次验证\n{'=' * 90}")
            r = await run_one(sm, i)
            so = r["structured_output"]
            print(f"response_len: {r['response_len']}")
            print(f"structured_output:")
            print(json.dumps(so, ensure_ascii=False, indent=2)[:800])

            if so:
                status = so.get("status", "?")
                if status == "EXPLOITABLE":
                    summary.append({"attempt": i, "result": "✅ EXPLOITABLE (正确)",
                                    "attack_vector": (so.get("attack_vector") or "")[:80]})
                elif status == "NOT_EXPLOITABLE":
                    defense = so.get("defense_analysis", "")
                    if defense and len(defense) >= 20:
                        summary.append({"attempt": i,
                                        "result": f"⚠️ NOT_EXPLOITABLE 但带 defense_analysis ({len(defense)} char)",
                                        "defense": defense[:120]})
                    else:
                        summary.append({"attempt": i, "result": "❌ NOT_EXPLOITABLE 无 defense_analysis（schema 应拦截）"})
                else:
                    summary.append({"attempt": i, "result": f"? status={status}"})
            else:
                summary.append({"attempt": i, "result": "❌ structured_output 为空"})
    finally:
        await sm.shutdown_all()

    print(f"\n{'#' * 90}\n汇总 (3 次重复)\n{'#' * 90}")
    exp_cnt = sum(1 for x in summary if x["result"].startswith("✅"))
    print(f"  {exp_cnt}/3 次判 EXPLOITABLE（修复前 v12 实测：0/1 次判 EXPLOITABLE）")
    for row in summary:
        print(f"\n  第 {row['attempt']} 次: {row['result']}")
        for k in ("attack_vector", "defense"):
            if k in row:
                print(f"      {k}: {row[k]}")


if __name__ == "__main__":
    asyncio.run(main())
