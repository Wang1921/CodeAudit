#!/usr/bin/env python3
"""CWE + severity classifier.

Called by the skill to deterministically map a vuln_type (from Semgrep rule
metadata.vuln_class) to CWE id + default severity. Ported verbatim from
CodeAudit's src/state_router.py so skill-generated reports match engine reports.

Usage:
    python3 classify.py <vuln_type> [max_impact]
    → prints JSON: {"cwe_id": "...", "severity": "..."}
"""
import json
import re
import sys

_VULN_TYPE_TO_CWE = {
    # 注入 & RCE
    "SQL Injection": "CWE-89",
    "Command Injection": "CWE-78",
    "Code Injection": "CWE-94",
    "LDAP Injection": "CWE-90",
    "XPath Injection": "CWE-643",
    "NoSQL Injection": "CWE-943",
    "Template Injection": "CWE-94",
    "SpEL Injection": "CWE-917",
    "JNDI Injection": "CWE-74",
    "JDBC URL Injection": "CWE-89",
    "Unsafe Deserialization": "CWE-502",
    "Unsafe Reflection": "CWE-470",
    # XML / SSRF
    "XXE": "CWE-611",
    "SSRF": "CWE-918",
    # 文件路径
    "Path Traversal": "CWE-22",
    "Zip Slip": "CWE-22",
    "Insecure Temp File": "CWE-377",
    # Web 输出
    "XSS": "CWE-79",
    "Open Redirect": "CWE-601",
    "Unvalidated Forward": "CWE-601",
    # 加密 / 随机 / 凭据
    "Weak Cryptography": "CWE-327",
    "Weak Random": "CWE-338",
    "Static IV": "CWE-329",
    "Constant Salt": "CWE-760",
    "Hardcoded Credentials": "CWE-798",
    "Insecure TLS": "CWE-295",
    "JWT None Algorithm": "CWE-347",
    # 会话 / Cookie / 边界
    "Insecure Cookie": "CWE-614",
    "Trust Boundary Violation": "CWE-501",
    # 信息泄露
    "Stack Trace Exposure": "CWE-209",
    "Sensitive Data in Log": "CWE-532",
    "Sensitive Data in URL": "CWE-598",
    # 业务逻辑类（LogicAuditor 白名单）
    "IDOR": "CWE-639",
    "Missing Authorization": "CWE-862",
    "Privilege Escalation": "CWE-269",
    "Authentication Bypass": "CWE-287",
    "Hardcoded Backdoor": "CWE-798",
    "Mass Assignment": "CWE-915",
    "Workflow Bypass": "CWE-840",
    "Race Condition": "CWE-362",
    "Insufficient Anti-Automation": "CWE-307",
}

_VULN_TYPE_TO_DEFAULT_SEVERITY = {
    # Critical — RCE / 全站认证绕过 / 凭据零距离泄露
    "SQL Injection": "Critical",
    "Command Injection": "Critical",
    "Code Injection": "Critical",
    "SpEL Injection": "Critical",
    "Template Injection": "Critical",
    "NoSQL Injection": "Critical",
    "JNDI Injection": "Critical",
    "JDBC URL Injection": "Critical",
    "Unsafe Deserialization": "Critical",
    "Unsafe Reflection": "Critical",
    "Hardcoded Credentials": "Critical",
    "Hardcoded Backdoor": "Critical",
    # High — 数据泄露 / 认证相关 / MITM / 权限越界
    "XXE": "High",
    "SSRF": "High",
    "Path Traversal": "High",
    "Zip Slip": "High",
    "LDAP Injection": "High",
    "XPath Injection": "High",
    "XSS": "High",
    "Weak Cryptography": "High",
    "Static IV": "High",
    "Constant Salt": "High",
    "JWT None Algorithm": "High",
    "Insecure TLS": "High",
    "Authentication Bypass": "High",
    "Privilege Escalation": "High",
    "IDOR": "High",
    "Mass Assignment": "High",
    "Missing Authorization": "High",
    # Medium
    "Weak Random": "Medium",
    "Open Redirect": "Medium",
    "Unvalidated Forward": "Medium",
    "Trust Boundary Violation": "Medium",
    "Insecure Cookie": "Medium",
    "Sensitive Data in Log": "Medium",
    "Sensitive Data in URL": "Medium",
    "Workflow Bypass": "Medium",
    "Race Condition": "Medium",
    "Insufficient Anti-Automation": "Medium",
    # Low
    "Stack Trace Exposure": "Low",
    "Insecure Temp File": "Low",
}


def extract_cwe_id(vuln_type: str, cwe_raw: str = "") -> str:
    """Prefer literal CWE-NNN in sink.metadata.cwe; fall back to vuln_type lookup."""
    m = re.match(r"(CWE-\d+)", cwe_raw or "")
    if m:
        return m.group(1)
    return _VULN_TYPE_TO_CWE.get(vuln_type, "")


def infer_severity(vuln_type: str, max_impact: str = "", explicit: str = "") -> str:
    """Priority: explicit > max_impact keywords > vuln_type default > Medium."""
    if explicit:
        s = explicit.strip().capitalize()
        if s in ("Critical", "High", "Medium", "Low"):
            return s
    impact = (max_impact or "").lower()
    if any(k in impact for k in ("rce", "remote code", "任意命令", "任意代码", "任意文件写")):
        return "Critical"
    if any(k in impact for k in ("sql", "数据泄露", "数据泄漏", "data leak", "认证绕过", "越权", "权限提升")):
        return "High"
    return _VULN_TYPE_TO_DEFAULT_SEVERITY.get(vuln_type, "Medium")


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: classify.py <vuln_type> [max_impact] [cwe_raw]"}))
        sys.exit(2)
    vuln_type = sys.argv[1]
    max_impact = sys.argv[2] if len(sys.argv) > 2 else ""
    cwe_raw = sys.argv[3] if len(sys.argv) > 3 else ""
    result = {
        "vuln_type": vuln_type,
        "cwe_id": extract_cwe_id(vuln_type, cwe_raw),
        "severity": infer_severity(vuln_type, max_impact),
    }
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
