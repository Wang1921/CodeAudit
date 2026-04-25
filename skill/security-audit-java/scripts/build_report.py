#!/usr/bin/env python3
"""确定性 markdown 报告生成器。

输入：一份已结构化的 findings JSON（由 skill 在阶段 1-5 完成证据裁决后产出）。
全程不调用 LLM —— 本脚本只是按模板把字段拼接成 markdown 文档。

用法：
    python3 build_report.py <findings.json> [输出.md]
    # 输出路径省略时默认写入 ./reports/audit-YYYYMMDD-HHMMSS.md

输入 JSON 结构：
    {
      "target_path": "/绝对路径/到/项目",
      "project_name": "可选覆盖",              # 默认取 target_path 末段
      "findings": [                           # 已确认的 VULNERABLE 发现
        {
          "vuln_type": "XSS",
          "cwe_id": "CWE-79",                 # 缺省时由 classify.py 自动补
          "severity": "High",                 # 缺省时由 classify.py 自动补
          "location": {"file": "...", "line": 56},
          "entry_route": "/path/...",
          "confidence": "HIGH",               # 可选
          "call_chain": ["1. ...", "2. ..."],
          "description": "...",
          "attack_vector": "...",
          "poc_payload": "...",
          "max_impact": "...",
          "mitigation_advice": "..."
        }
      ],
      "defended": [                           # 可选 —— 假阳性候选
        {
          "location": {"file": "...", "line": 91},
          "vuln_type": "Path Traversal",
          "defense_analysis": "..."
        }
      ]
    }
"""
import collections
import datetime
import json
import os
import sys
from pathlib import Path

# Reuse classify.py for CWE / severity fallback
_SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT_DIR))
from classify import extract_cwe_id, infer_severity  # noqa: E402


_SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def _enrich(finding: dict) -> dict:
    """缺失的 cwe_id / severity 通过 classify.py 自动补全。"""
    vt = finding.get("vuln_type", "")
    if not finding.get("cwe_id"):
        finding["cwe_id"] = extract_cwe_id(vt, finding.get("cwe", ""))
    if not finding.get("severity"):
        finding["severity"] = infer_severity(
            vt,
            finding.get("max_impact", ""),
            finding.get("severity_hint", ""),
        )
    return finding


def _severity_sort_key(f: dict) -> tuple:
    return (_SEVERITY_ORDER.get(f.get("severity", "Medium"), 2), f.get("vuln_type", ""))


def _format_finding(idx: int, f: dict) -> str:
    loc = f.get("location", {})
    file = loc.get("file", "unknown")
    line = loc.get("line", "?")
    call_chain = f.get("call_chain") or []
    if isinstance(call_chain, str):
        call_chain = [call_chain]
    cc_md = "\n".join(f"- {step}" for step in call_chain) or "- N/A"

    return f"""### [VULN-{idx:03d}] {f.get('vuln_type', 'Unknown')} — `{file}:{line}`

| 字段 | 值 |
|---|---|
| **CWE** | {f.get('cwe_id', 'N/A')} |
| **严重度** | {f.get('severity', 'Medium')} |
| **入口路由** | {f.get('entry_route', 'N/A')} |
| **置信度** | {f.get('confidence', 'MEDIUM')} |

**调用链**：
{cc_md}

**漏洞描述**：
{f.get('description', '-')}

**攻击向量**：
{f.get('attack_vector', '-')}

**PoC payload**：
```
{f.get('poc_payload', '-')}
```

**最大影响**：{f.get('max_impact', '-')}

**修复建议**：
{f.get('mitigation_advice', '-')}

---
"""


def _format_defended(items: list) -> str:
    if not items:
        return ""
    lines = ["## 假阳性候选（DEFENDED）", ""]
    lines.append("以下条目被 Semgrep 标记，但根据代码内联证据被裁决为不可利用。")
    lines.append("")
    for d in items:
        loc = d.get("location", {})
        file = loc.get("file", "unknown")
        line = loc.get("line", "?")
        reason = d.get("defense_analysis", "无分析说明")
        lines.append(f"- `{file}:{line}` — {d.get('vuln_type', 'Unknown')}：{reason}")
    lines.append("")
    return "\n".join(lines)


def build_report(data: dict) -> str:
    target = data.get("target_path", "unknown")
    project = data.get("project_name") or os.path.basename(target.rstrip("/")) or "project"
    date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    findings = [_enrich(dict(f)) for f in data.get("findings", [])]
    findings.sort(key=_severity_sort_key)

    sev_count = collections.Counter(f.get("severity", "Medium") for f in findings)
    cat_count = collections.Counter(f.get("vuln_type", "Unknown") for f in findings)

    header = f"""# 安全审计报告 — {project}

- **日期**：{date}
- **目标**：`{target}`
- **发现总数**：{len(findings)}
- **按严重度**：Critical {sev_count.get('Critical', 0)} / High {sev_count.get('High', 0)} / Medium {sev_count.get('Medium', 0)} / Low {sev_count.get('Low', 0)}
- **按类别**：{", ".join(f"{k} ({v})" for k, v in cat_count.most_common()) or "无"}

---

## 漏洞清单
"""
    if not findings:
        findings_md = "_经过证据裁决后无 VULNERABLE 发现。_\n\n---\n"
    else:
        findings_md = "\n".join(_format_finding(i + 1, f) for i, f in enumerate(findings))

    defended_md = _format_defended(data.get("defended", []))

    return header + "\n" + findings_md + "\n" + defended_md


def main():
    if len(sys.argv) < 2:
        print("用法：build_report.py <findings.json> [输出.md]", file=sys.stderr)
        sys.exit(2)

    with open(sys.argv[1], "r", encoding="utf-8") as f:
        data = json.load(f)

    if len(sys.argv) > 2:
        out_path = sys.argv[2]
    else:
        ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        out_dir = Path(data.get("target_path", ".")) / "reports"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = str(out_dir / f"audit-{ts}.md")

    report = build_report(data)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(report)
    print(out_path)


if __name__ == "__main__":
    main()
