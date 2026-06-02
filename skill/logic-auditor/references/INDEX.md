# Reference Index — 漏洞类型 → 分析步骤文档映射

按 finding 的 `vuln_type` 查下表找到对应的 reference 文档，
**严格按文档的"sink 模式 / 数据流追溯 / 防御机制 / 常见误判 / 证据引用 / PoC 模板"6 段流程**执行。

## 映射表

| `vuln_type` | reference 文档 |
|---|---|
| **IDOR** | [authz-family.md](authz-family.md) |
| **Missing Authorization** | [authz-family.md](authz-family.md) |
| **Privilege Escalation** | [authz-family.md](authz-family.md) |
| **Authentication Bypass** | [authz-family.md](authz-family.md) |
| **Hardcoded Backdoor** | [credentials-backdoor.md](credentials-backdoor.md) |
| **Mass Assignment** | [business-logic-family.md](business-logic-family.md) |
| **Workflow Bypass** | [business-logic-family.md](business-logic-family.md) |
| **Race Condition** | [business-logic-family.md](business-logic-family.md) |
| **Open Redirect** | [redirect-family.md](redirect-family.md) |
| **Insufficient Anti-Automation** | [business-logic-family.md](business-logic-family.md) |
