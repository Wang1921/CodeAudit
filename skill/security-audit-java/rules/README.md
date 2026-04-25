# 规则目录

本目录存放驱动 skill 工作的 Semgrep YAML 规则文件，需要与上游 CodeAudit 项目保持同步。

## 安装 / 同步

在 CodeAudit 仓库根目录执行：

```bash
cp semgrep_rules/custom/*.yaml skill/security-audit-java/rules/
```

如果要直接装到 `~/.claude/skills/`：

```bash
mkdir -p ~/.claude/skills/security-audit-java/rules
cp semgrep_rules/custom/*.yaml ~/.claude/skills/security-audit-java/rules/
```

## 规则清单（约 40 条）

详细列表见 SKILL.md。规则按 `metadata.taint_required` 分两类：

**污点链类**（`taint_required: true` 默认）—— 需要追踪 source → sink：
- sql-injection / mybatis-xml-sql-injection / command-injection / code-injection
- path-traversal / zip-slip
- ldap-injection / xpath-injection / nosql-injection / template-injection
- spel-injection / xxe / ssrf
- unsafe-deserialization / unsafe-reflection
- jndi-injection / jdbc-url-tainted
- xss / open-redirect / unvalidated-forward

**Fast-path 类**（`taint_required: false`）—— sink 结构本身即漏洞：
- weak-cryptography / weak-random / insecure-crypto-config（static-iv / constant-salt / insufficient-key）
- hardcoded-credentials / insecure-trust-manager / jwt-none
- insecure-cookie / trust-boundary
- sensitive-data-in-log / sensitive-data-in-url
- stack-trace-exposure / insecure-temp-file

**路由提取类**（供 LogicAuditor 使用，不是漏洞规则）：
- spring-api

每条规则的 `metadata.vuln_class` 字段是该规则下游统一使用的 `vuln_type` 命名 key。
**严禁翻译 / 改写** —— 各 Agent 之间靠这个字符串做去重和聚合。
