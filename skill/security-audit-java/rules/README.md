# Rules

This directory should contain the Semgrep YAML rules that drive the skill.
Keep it in sync with the upstream CodeAudit project.

## Install / sync

From the CodeAudit repo root:

```bash
cp semgrep_rules/custom/*.yaml skill/security-audit-java/rules/
```

Or if you're installing the skill into `~/.claude/skills/`:

```bash
mkdir -p ~/.claude/skills/security-audit-java/rules
cp semgrep_rules/custom/*.yaml ~/.claude/skills/security-audit-java/rules/
```

## Current rule inventory

Should have ~30 rules covering (see `SKILL.md` for full list):

**Taint-chain sinks** (`taint_required: true`, default):
- sql-injection, mybatis-xml-sql-injection, command-injection, code-injection
- path-traversal, zip-slip
- ldap-injection, xpath-injection, nosql-injection, template-injection
- spel-injection, xxe, ssrf
- unsafe-deserialization, unsafe-reflection
- jndi-injection, jdbc-url-tainted
- xss, open-redirect, unvalidated-forward

**Fast-path sinks** (`taint_required: false`):
- weak-cryptography, weak-random, insecure-crypto-config (static-iv / constant-salt / insufficient-key)
- hardcoded-credentials, insecure-trust-manager, jwt-none
- insecure-cookie, trust-boundary
- sensitive-data-in-log, sensitive-data-in-url
- stack-trace-exposure, insecure-temp-file

**Route extraction** (for future LogicAuditor integration):
- spring-api

Each rule's `metadata.vuln_class` is the canonical `vuln_type` used downstream.
Don't translate / rewrite — verbatim copy into report.
