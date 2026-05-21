---
name: security-audit-java
description: Java 安全审计 Agent 运行时指导。当 ReverseTracer / RedValidator / BlueValidator / LogicAuditor 任一 Agent 运行时，按角色加载对应的领域知识。当用户在 Java 项目语境下提出安全审计需求时触发。支持 Maven / Gradle / 多模块项目。兼容 OpenCode 与 Claude Code。
---

# Java 安全审计 Agent 运行时指导

本 Skill 为 CodeAudit 引擎的各 Agent 提供运行时领域知识，不独立执行扫描。
扫描由引擎的 SemgrepScanner 完成，Agent 按角色分工协作完成漏洞验证和裁决。

## 如何使用

当你作为某个 Agent 角色工作时，用 `read` 工具读取对应的指导文档：

| 你的角色 | 读取此文件 |
|---|---|
| **ReverseTracer** | `$SKILL_DIR/guides/reverse-tracer.md` |
| **RedValidator** | `$SKILL_DIR/guides/red-validator.md` |
| **BlueValidator** | `$SKILL_DIR/guides/blue-validator.md` |
| **LogicAuditor** | `$SKILL_DIR/guides/logic-auditor.md` |

需要按漏洞类型查阅深度分析时，读取 `$SKILL_DIR/reference/INDEX.md` 找到对应文档。

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

## 共享约束

- **vuln_type 不可修改**：必须逐字复制上游分类，该字段是全链路去重和 CWE 映射的唯一 key
- **证据必须引用代码**：行号或代码片段，不接受纯文字描述
- **禁止项目类别辩护**：不以"教学/演示/测试项目"作为安全理由
