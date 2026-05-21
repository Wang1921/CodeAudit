---
name: security-audit-java
description: Java 安全审计 Agent 运行时指导。为 CodeAudit 引擎的 4 个专业 Agent（ReverseTracer / RedValidator / BlueValidator / LogicAuditor）提供领域知识注入。当用户在 Java 项目语境下提出安全审计需求时触发。支持 Maven / Gradle / 多模块项目。兼容 OpenCode 与 Claude Code。
---

# Java 安全审计 Agent 运行时指导

本 Skill 为 CodeAudit 引擎的各 Agent 提供运行时领域知识，不独立执行扫描。
扫描由引擎的 SemgrepScanner 完成，Agent 按角色分工协作完成漏洞验证和裁决。

## Agent 角色概览

| Agent | 职责 | 指导文档 |
|---|---|---|
| **ReverseTracer** | 从 sink 逆向追踪污点变量至外部入口 | [guides/reverse-tracer.md](guides/reverse-tracer.md) |
| **RedValidator** | 验证可利用性，构造攻击向量和 PoC | [guides/red-validator.md](guides/red-validator.md) |
| **BlueValidator** | 最终裁决：防御是否有效 / 静态 sink 定性 | [guides/blue-validator.md](guides/blue-validator.md) |
| **LogicAuditor** | 审查 API 路由的业务逻辑安全 | [guides/logic-auditor.md](guides/logic-auditor.md) |

## Agent 协作流程

```
SemgrepScanner ──→ ReverseTracer ──→ RedValidator ──→ BlueValidator ──→ Report
       │                                      ↑
       └──→ LogicAuditor ─────────────────────┘
```

1. SemgrepScanner 扫描目标项目，产出 sink 点和 API 路由
2. Sink → ReverseTracer 追踪污点链 → RedValidator 验证可利用性 → BlueValidator 最终裁决
3. API 路由 → LogicAuditor 审查业务逻辑 → RedValidator → BlueValidator
4. BlueValidator 输出最终裁定（VULNERABLE / DEFENDED）→ 汇入报告

## 漏洞类型参考

各 Agent 按漏洞类型查阅深度分析文档：[reference/INDEX.md](reference/INDEX.md)

## 共享约束

- **vuln_type 不可修改**：必须逐字复制上游分类，该字段是全链路去重和 CWE 映射的唯一 key
- **证据必须引用代码**：行号或代码片段，不接受纯文字描述
- **禁止项目类别辩护**：不以"教学/演示/测试项目"作为安全理由
