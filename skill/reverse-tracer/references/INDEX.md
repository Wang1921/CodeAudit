# Reference Index — 漏洞类型 → 分析步骤文档映射

按 finding 的 `vuln_type` 查下表找到对应的 reference 文档。
本 skill 版本文档仅包含 **sink 模式速查 / 数据流追溯重点 / 常见误判** 段落（溯源所需），
不含防御机制或 PoC 模板（由下游 red-validator / blue-validator 的 skill 提供）。

未在表内的 `vuln_type` 按"injection-family.md"的通用模板处理。

## 映射表

| `vuln_type` (来自 Semgrep `metadata.vuln_class`) | reference 文档 |
|---|---|
| **SQL Injection** | [injection-family.md](injection-family.md) |
| **NoSQL Injection** | [injection-family.md](injection-family.md) |
| **Command Injection** | [injection-family.md](injection-family.md) |
| **Code Injection** | [injection-family.md](injection-family.md) |
| **LDAP Injection** | [injection-family.md](injection-family.md) |
| **XPath Injection** | [injection-family.md](injection-family.md) |
| **Template Injection** | [injection-family.md](injection-family.md) |
| **SpEL Injection** | [injection-family.md](injection-family.md) |
| **JNDI Injection** | [injection-family.md](injection-family.md) |
| **JDBC URL Injection** | [injection-family.md](injection-family.md) |
| **Unsafe Deserialization** | [deserialization-reflection.md](deserialization-reflection.md) |
| **Unsafe Reflection** | [deserialization-reflection.md](deserialization-reflection.md) |
| **XXE** | [xxe.md](xxe.md) |
| **SSRF** | [ssrf.md](ssrf.md) |
| **Path Traversal** | [path-traversal-family.md](path-traversal-family.md) |
| **Zip Slip** | [path-traversal-family.md](path-traversal-family.md) |
| **Insecure Temp File** | [path-traversal-family.md](path-traversal-family.md) |
| **XSS** | [xss.md](xss.md) |
| **Open Redirect** | [redirect-family.md](redirect-family.md) |
| **Unvalidated Forward** | [redirect-family.md](redirect-family.md) |
| **Weak Cryptography** | [crypto-family.md](crypto-family.md) |
| **Weak Random** | [crypto-family.md](crypto-family.md) |
| **Insecure TLS** | [crypto-family.md](crypto-family.md) |
| **JWT None Algorithm** | [crypto-family.md](crypto-family.md) |
| **Hardcoded Credentials** | [credentials-backdoor.md](credentials-backdoor.md) |
| **Hardcoded Backdoor** | [credentials-backdoor.md](credentials-backdoor.md) |
| **Insecure Cookie** | [cookie-trust-boundary.md](cookie-trust-boundary.md) |
| **Trust Boundary Violation** | [cookie-trust-boundary.md](cookie-trust-boundary.md) |
| **Stack Trace Exposure** | [info-disclosure.md](info-disclosure.md) |
| **Sensitive Data in Log** | [info-disclosure.md](info-disclosure.md) |
| **Sensitive Data in URL** | [info-disclosure.md](info-disclosure.md) |
| **IDOR** | [authz-family.md](authz-family.md) |
| **Missing Authorization** | [authz-family.md](authz-family.md) |
| **Privilege Escalation** | [authz-family.md](authz-family.md) |
| **Authentication Bypass** | [authz-family.md](authz-family.md) |
| **Mass Assignment** | [business-logic-family.md](business-logic-family.md) |
| **Workflow Bypass** | [business-logic-family.md](business-logic-family.md) |
| **Race Condition** | [business-logic-family.md](business-logic-family.md) |
| **Insufficient Anti-Automation** | [business-logic-family.md](business-logic-family.md) |
