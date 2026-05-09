"""漏洞汇总报告生成器（无 LLM）。

读取 reports/ 下所有 vulnerability_*.json，按严重度排序聚合为一份
markdown 总览：

- 顶部概览（按严重度 + 按类别 + 按文件 计数）
- 详细列表（按 severity Critical→Low 排序，包含调用链）
- 失败任务统计（如果 .a2a_bus/failed/ 存在）

用法：
    python3 -m src.build_summary_report                      # 输出到 reports/SUMMARY.md
    python3 -m src.build_summary_report --reports DIR        # 自定义 reports/ 路径
    python3 -m src.build_summary_report --target-dir DIR     # 同时统计 DIR/.a2a_bus/failed/
    python3 -m src.build_summary_report --output PATH        # 自定义输出路径
"""
import argparse
import collections
import datetime
import glob
import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def _load_reports(reports_dir: str) -> List[Dict[str, Any]]:
    findings = []
    for fp in sorted(glob.glob(os.path.join(reports_dir, "vulnerability_*.json"))):
        try:
            with open(fp, "r", encoding="utf-8") as f:
                data = json.load(f)
            findings.append(data)
        except Exception as e:
            logger.warning(f"跳过无法解析的报告 {fp}: {e}")
    return findings


def _severity_key(f: Dict[str, Any]):
    return (
        _SEVERITY_ORDER.get(f.get("severity", "Medium"), 2),
        f.get("vuln_type", ""),
        f.get("task_id", ""),
    )


def _short(text: Any, n: int = 200) -> str:
    s = "" if text is None else str(text)
    s = s.strip().replace("\r", "")
    if len(s) <= n:
        return s
    return s[:n].rstrip() + "…"


def _format_call_chain(cc: Any) -> str:
    if not cc:
        return "_（无调用链信息）_"
    if isinstance(cc, str):
        s = cc.strip()
        # 兼容 LLM 偶尔把数组序列化成 JSON 字符串的情况
        if s.startswith("[") and s.endswith("]"):
            try:
                cc = json.loads(s)
            except Exception:
                return s
        else:
            return s
    if isinstance(cc, list):
        if not cc:
            return "_（无调用链信息）_"
        lines = []
        for step in cc:
            step_str = step.strip() if isinstance(step, str) else json.dumps(step, ensure_ascii=False)
            lines.append(f"- {step_str}")
        return "\n".join(lines)
    return str(cc)


def _failed_stats(target_dir: Optional[str]) -> Dict[str, int]:
    if not target_dir:
        return {}
    failed_dir = os.path.join(target_dir, ".a2a_bus", "failed")
    if not os.path.isdir(failed_dir):
        return {}
    stats = collections.Counter()
    for fp in glob.glob(os.path.join(failed_dir, "*.json")):
        name = os.path.basename(fp)
        if "_TRACE_" in name:
            stats["TRACE"] += 1
        elif "_STATIC_" in name:
            stats["STATIC"] += 1
        elif "_ROUTE_" in name:
            stats["ROUTE"] += 1
        else:
            stats["OTHER"] += 1
    stats["TOTAL"] = sum(stats.values())
    return dict(stats)


def _format_overview(findings: List[Dict[str, Any]], target_dir: Optional[str]) -> str:
    sev_count = collections.Counter(f.get("severity", "Medium") for f in findings)
    type_count = collections.Counter(f.get("vuln_type", "Unknown") for f in findings)
    file_count = collections.Counter(
        os.path.basename(f.get("location", {}).get("file", "")) for f in findings
    )
    file_count.pop("", None)

    lines = [
        f"**生成时间**：{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**漏洞总数**：{len(findings)}",
        "",
        "## 按严重度",
        "",
        "| Critical | High | Medium | Low |",
        "|---:|---:|---:|---:|",
        f"| {sev_count.get('Critical', 0)} | {sev_count.get('High', 0)} | {sev_count.get('Medium', 0)} | {sev_count.get('Low', 0)} |",
        "",
    ]

    if type_count:
        lines += ["## 按漏洞类型", "", "| 类型 | CWE | 数量 |", "|---|---|---:|"]
        # 同 vuln_type 取第一个 CWE
        cwe_by_type = {}
        for f in findings:
            vt = f.get("vuln_type", "Unknown")
            if vt not in cwe_by_type:
                cwe_by_type[vt] = f.get("cwe_id", "")
        for vt, n in type_count.most_common():
            lines.append(f"| {vt} | {cwe_by_type.get(vt, '')} | {n} |")
        lines.append("")

    if file_count:
        lines += ["## 按文件 Top 10", "", "| 文件 | 命中数 |", "|---|---:|"]
        for fn, n in file_count.most_common(10):
            lines.append(f"| `{fn}` | {n} |")
        lines.append("")

    failed = _failed_stats(target_dir)
    if failed:
        lines += ["## 失败任务统计（.a2a_bus/failed/）", ""]
        lines.append(f"- 失败总数：**{failed.get('TOTAL', 0)}**")
        for k in ("TRACE", "STATIC", "ROUTE", "OTHER"):
            if failed.get(k):
                lines.append(f"  - {k}：{failed[k]}")
        lines.append("")
        lines.append(
            "_失败任务多为 LLM HTTP 超时 / 解析失败导致，未生成报告。_"
        )
        lines.append("")
    return "\n".join(lines)


def _format_finding(idx: int, f: Dict[str, Any]) -> str:
    loc = f.get("location") or {}
    file = loc.get("file", "未知")
    line = loc.get("line", "?")

    cwe = f.get("cwe_id", "")
    severity = f.get("severity", "Medium")
    vuln_type = f.get("vuln_type", "Unknown")
    entry = f.get("entry_route", "未知")
    task_id = f.get("task_id", "")

    header = f"### [VULN-{idx:03d}] {vuln_type} — `{os.path.basename(file)}:{line}`"

    meta_table = (
        "| 字段 | 值 |\n"
        "|---|---|\n"
        f"| **CWE** | {cwe or '—'} |\n"
        f"| **严重度** | {severity} |\n"
        f"| **入口路由** | {entry} |\n"
        f"| **完整路径** | `{file}` |\n"
        f"| **task_id** | `{task_id}` |\n"
    )

    cc_md = _format_call_chain(f.get("call_chain"))

    sections = [
        header,
        "",
        meta_table,
        "**调用链**：",
        "",
        cc_md,
        "",
    ]

    description = f.get("description") or f.get("suspicion_reason")
    if description:
        sections += ["**漏洞描述**：", "", _short(description, 1200), ""]

    av = f.get("attack_vector")
    if av:
        sections += ["**攻击向量**：", "", _short(av, 600), ""]

    poc = f.get("poc_payload")
    if poc:
        sections += ["**PoC payload**：", "", "```", _short(poc, 800), "```", ""]

    impact = f.get("max_impact")
    if impact:
        sections += [f"**最大影响**：{_short(impact, 300)}", ""]

    mitig = f.get("remediation") or f.get("mitigation_advice")
    if mitig:
        sections += ["**修复建议**：", "", _short(mitig, 600), ""]

    defense = f.get("defense_analysis")
    if defense:
        sections += ["**防御分析**：", "", _short(defense, 400), ""]

    sections.append("---")
    sections.append("")
    return "\n".join(sections)


def build_summary(reports_dir: str, target_dir: Optional[str], project_name: str) -> str:
    findings = _load_reports(reports_dir)
    findings.sort(key=_severity_key)

    title = f"# 安全审计汇总报告 — {project_name}"
    overview = _format_overview(findings, target_dir)

    if not findings:
        body = "_经审计未发现 VULNERABLE 漏洞。_"
    else:
        body = "## 漏洞清单\n\n" + "\n".join(
            _format_finding(i + 1, f) for i, f in enumerate(findings)
        )

    return "\n".join([title, "", overview, body])


def main():
    parser = argparse.ArgumentParser(description="生成漏洞审计汇总报告")
    parser.add_argument("--reports", default="reports", help="reports 目录路径（默认 ./reports）")
    parser.add_argument("--target-dir", default=None, help="被审计项目目录，用于读取 .a2a_bus/failed/ 失败统计")
    parser.add_argument("--output", default=None, help="输出 markdown 路径（默认 <reports>/SUMMARY.md）")
    parser.add_argument("--project-name", default=None, help="项目名（默认取 target-dir basename）")
    args = parser.parse_args()

    if not os.path.isdir(args.reports):
        print(f"reports 目录不存在：{args.reports}", file=sys.stderr)
        sys.exit(1)

    output = args.output or os.path.join(args.reports, "SUMMARY.md")
    project = args.project_name or (
        os.path.basename(args.target_dir.rstrip("/")) if args.target_dir else "未命名项目"
    )

    markdown = build_summary(args.reports, args.target_dir, project)
    with open(output, "w", encoding="utf-8") as f:
        f.write(markdown)
    print(output)


if __name__ == "__main__":
    main()
