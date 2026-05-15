#!/usr/bin/env python3
"""Semgrep 结果分流脚本（替代 LLM 做 fast-path + 去重）。

输入：scan.sh 的 JSON 输出路径
输出：
  - findings_fast.json：可直接产报告的 fast-path findings（metadata.taint_required: false）
                       例如 Weak Random / Hardcoded Credentials / Insecure Cookie 这类
                       "sink 即漏洞" 的静态定性 sink，无需污点链追踪
  - pending_llm.json：必须由 LLM 做污点追踪 + 证据裁决的 results
                     （metadata.taint_required: true 或缺省）
  - stats.json：分流统计（raw / dedup / fast / pending 计数）

设计意图：
  v12 baseline 实测在主引擎里也类似的痛点：LLM 拿到 30+ Semgrep results 后倾向于
  整体归并而非逐条裁决。把 fast-path 类型先用脚本处理掉（无需 LLM），LLM 实际只看
  需要污点链推理的 8-12 条，每条都能深入分析。

用法：
    python3 dispatch.py <semgrep_json> [--out-dir DIR]
    # 默认 out-dir 是 semgrep_json 的同目录
    # 输出三个文件：findings_fast.json / pending_llm.json / stats.json
"""
import argparse
import json
import os
import sys
from pathlib import Path

# Reuse classify.py 做 CWE + 严重度 enrich
_SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT_DIR))
from classify import extract_cwe_id, infer_severity  # noqa: E402


def _is_vulnerability_rule(result: dict) -> bool:
    """metadata.vuln_class 非空 → 是漏洞 sink；否则是路由发现/工具规则，跳过。

    spring-api.yaml 等"路由发现"规则不设 vuln_class（它们的目的是给 LogicAuditor 喂入
    口路由信息，skill 单 LLM 模式不需要这一层）。剔除这类命中能让 pending_llm 列表
    只包含真实漏洞候选，让 LLM 不被路由噪音淹没。
    """
    meta = result.get("extra", {}).get("metadata", {}) or {}
    return bool((meta.get("vuln_class") or "").strip())


def _dedup_and_filter(results: list) -> tuple[list, int]:
    """按 (vuln_class, path, line) 去重 + 剔除非漏洞规则。

    返回 (有效 results 列表, 被过滤掉的非漏洞规则计数)。
    """
    seen = set()
    out = []
    filtered_non_vuln = 0
    for r in results:
        if not _is_vulnerability_rule(r):
            filtered_non_vuln += 1
            continue
        meta = r.get("extra", {}).get("metadata", {}) or {}
        vc = meta.get("vuln_class") or r.get("check_id", "")
        path = r.get("path", "")
        line = r.get("start", {}).get("line", 0)
        key = (vc, path, line)
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out, filtered_non_vuln


def _is_fast_path(result: dict) -> bool:
    """metadata.taint_required: false 即 fast-path（无需污点链）。

    缺省视为 true（需要 LLM 验证），保守起见。
    """
    meta = result.get("extra", {}).get("metadata", {}) or {}
    return meta.get("taint_required") is False


def _to_fast_finding(result: dict) -> dict:
    """fast-path result → 标准 finding 字典（直接进 build_report.py）。"""
    meta = result.get("extra", {}).get("metadata", {}) or {}
    extra = result.get("extra", {})
    vuln_type = meta.get("vuln_class") or ""
    cwe_raw = ""
    if isinstance(meta.get("cwe"), list) and meta["cwe"]:
        cwe_raw = meta["cwe"][0]
    elif isinstance(meta.get("cwe"), str):
        cwe_raw = meta["cwe"]

    cwe_id = extract_cwe_id(vuln_type, cwe_raw)
    severity = infer_severity(vuln_type, max_impact="", explicit=meta.get("severity_hint", ""))

    # Semgrep 的 severity 也可能直接定 ERROR/WARNING/INFO，映射成 Critical/High/Medium
    raw_sev = result.get("extra", {}).get("severity", "")
    if not severity or severity == "Medium":
        if raw_sev == "ERROR":
            severity = severity if severity != "Medium" else "High"
        elif raw_sev == "WARNING":
            severity = severity if severity != "Medium" else "Medium"

    return {
        "vuln_type": vuln_type,
        "cwe_id": cwe_id,
        "severity": severity,
        "location": {
            "file": result.get("path", ""),
            "line": result.get("start", {}).get("line", 0),
        },
        "entry_route": "",  # fast-path 不追踪 entry_route
        "confidence": meta.get("confidence", "MEDIUM"),
        "call_chain": ["N/A（静态定性 sink，无需污点链）"],
        "description": (extra.get("message") or "").strip()[:500],
        "suspicion_reason": "Semgrep fast-path 命中：" + (extra.get("message") or "").strip()[:200],
        "defense_analysis": "fast-path 类型，未做防御核查（如需深查请改为 taint_required: true 让 LLM 验证）。",
        "attack_vector": "N/A（fast-path 静态定性，无需构造攻击向量）",
        "poc_payload": "N/A",
        "max_impact": "见漏洞描述",
        "mitigation_advice": (extra.get("message") or "").split("修复建议")[-1].strip()[:300] if "修复建议" in (extra.get("message") or "") else "请参照 OWASP / CWE 文档",
        "_source": "fast-path",  # 内部字段，方便报告分组
    }


def _to_pending_entry(result: dict) -> dict:
    """需要 LLM 处理的 result → 精简结构（喂给 LLM 时 token 友好）。"""
    meta = result.get("extra", {}).get("metadata", {}) or {}
    extra = result.get("extra", {})
    return {
        "id": f"{meta.get('vuln_class','?')}:{result.get('path','?')}:{result.get('start',{}).get('line',0)}",
        "vuln_type": meta.get("vuln_class") or "",
        "cwe": meta.get("cwe") if isinstance(meta.get("cwe"), (str, list)) else "",
        "confidence": meta.get("confidence", "MEDIUM"),
        "filepath": result.get("path", ""),
        "line": result.get("start", {}).get("line", 0),
        "end_line": result.get("end", {}).get("line", 0),
        "snippet": extra.get("lines", "").strip()[:300],
        "message": (extra.get("message") or "").strip()[:300],
        "_check_id": result.get("check_id", ""),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("semgrep_json", help="scan.sh 输出的 JSON 路径")
    ap.add_argument("--out-dir", default="", help="输出目录（默认 = semgrep_json 同目录）")
    args = ap.parse_args()

    with open(args.semgrep_json, encoding="utf-8") as f:
        data = json.load(f)

    raw_results = data.get("results", [])

    deduped, non_vuln_count = _dedup_and_filter(raw_results)

    fast_findings = []
    pending_llm = []
    for r in deduped:
        if _is_fast_path(r):
            fast_findings.append(_to_fast_finding(r))
        else:
            pending_llm.append(_to_pending_entry(r))

    out_dir = Path(args.out_dir or Path(args.semgrep_json).parent)
    out_dir.mkdir(parents=True, exist_ok=True)

    fast_path = out_dir / "findings_fast.json"
    pending_path = out_dir / "pending_llm.json"
    stats_path = out_dir / "dispatch_stats.json"

    fast_path.write_text(json.dumps(fast_findings, ensure_ascii=False, indent=2), encoding="utf-8")
    pending_path.write_text(json.dumps(pending_llm, ensure_ascii=False, indent=2), encoding="utf-8")

    stats = {
        "raw_results": len(raw_results),
        "filtered_non_vuln": non_vuln_count,
        "after_dedup_and_filter": len(deduped),
        "fast_findings": len(fast_findings),
        "pending_llm": len(pending_llm),
        "files": {
            "fast": str(fast_path),
            "pending": str(pending_path),
        },
    }
    stats_path.write_text(json.dumps(stats, ensure_ascii=False, indent=2), encoding="utf-8")

    # 同时打印到 stdout 方便 SKILL.md 用 bash 解析
    print(json.dumps(stats, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
