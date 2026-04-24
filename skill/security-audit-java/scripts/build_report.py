#!/usr/bin/env python3
"""Deterministic markdown report generator.

Input: JSON file with structured findings (produced by the skill after its
Phase 1-5 evidence judgment). No LLM involved — this script only shuffles
data into the report template.

Usage:
    python3 build_report.py <findings.json> [output.md]
    # if output.md omitted, defaults to ./reports/audit-YYYYMMDD-HHMMSS.md

Input JSON schema:
    {
      "target_path": "/abs/path/to/project",
      "project_name": "optional-override",    # defaults to basename of target_path
      "findings": [                           # VULNERABLE confirmed cases
        {
          "vuln_type": "XSS",
          "cwe_id": "CWE-79",                 # if missing, will be filled via classify.py
          "severity": "High",                 # if missing, will be filled via classify.py
          "location": {"file": "...", "line": 56},
          "entry_route": "/path/...",
          "confidence": "HIGH",               # optional
          "call_chain": ["1. ...", "2. ..."],
          "description": "...",
          "attack_vector": "...",
          "poc_payload": "...",
          "max_impact": "...",
          "mitigation_advice": "..."
        }
      ],
      "defended": [                           # optional — false-positive candidates
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
    """Fill missing cwe_id / severity by consulting classify.py."""
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

| Field | Value |
|---|---|
| **CWE** | {f.get('cwe_id', 'N/A')} |
| **Severity** | {f.get('severity', 'Medium')} |
| **Entry route** | {f.get('entry_route', 'N/A')} |
| **Confidence** | {f.get('confidence', 'MEDIUM')} |

**Call chain**:
{cc_md}

**Description**:
{f.get('description', '-')}

**Attack vector**:
{f.get('attack_vector', '-')}

**PoC payload**:
```
{f.get('poc_payload', '-')}
```

**Max impact**: {f.get('max_impact', '-')}

**Mitigation**:
{f.get('mitigation_advice', '-')}

---
"""


def _format_defended(items: list) -> str:
    if not items:
        return ""
    lines = ["## False-positive candidates (DEFENDED)", ""]
    lines.append("These were flagged by Semgrep but judged non-exploitable on inline evidence.")
    lines.append("")
    for d in items:
        loc = d.get("location", {})
        file = loc.get("file", "unknown")
        line = loc.get("line", "?")
        reason = d.get("defense_analysis", "no analysis")
        lines.append(f"- `{file}:{line}` — {d.get('vuln_type', 'Unknown')}: {reason}")
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

    header = f"""# Security Audit Report — {project}

- **Date**: {date}
- **Target**: `{target}`
- **Total findings**: {len(findings)}
- **By severity**: Critical {sev_count.get('Critical', 0)} / High {sev_count.get('High', 0)} / Medium {sev_count.get('Medium', 0)} / Low {sev_count.get('Low', 0)}
- **By category**: {", ".join(f"{k} ({v})" for k, v in cat_count.most_common()) or "none"}

---

## Findings
"""
    if not findings:
        findings_md = "_No VULNERABLE findings after validation._\n\n---\n"
    else:
        findings_md = "\n".join(_format_finding(i + 1, f) for i, f in enumerate(findings))

    defended_md = _format_defended(data.get("defended", []))

    return header + "\n" + findings_md + "\n" + defended_md


def main():
    if len(sys.argv) < 2:
        print("usage: build_report.py <findings.json> [output.md]", file=sys.stderr)
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
