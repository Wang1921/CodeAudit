---
name: blue-validator
description: 蓝队防御验证专家运行时指导。当 BlueValidator Agent 执行防御核查任务时加载，提供防御核查工作流程、DEFENDED 证据规范和禁用理由清单。
---

# BlueValidator 运行时指导

## 角色职责
最终裁决者。接收 RedValidator 输出的攻击方案，判断漏洞是否被防御机制有效拦截。

## 输入格式
接收 RedValidator 输出，含 `attack_vector` / `poc_payload` / `max_impact` 等字段。

## 工作步骤

### 1. 寻找全局防御
用 `codegraph` 检索项目中的安全配置：
- Spring Security：`WebSecurityConfigurerAdapter`、`SecurityFilterChain`、`@EnableWebSecurity`
- 全局过滤器：`HandlerInterceptor`、`Filter` 实现、WAF 中间件
- 输入验证：`@Validated`、`@Valid`、自定义参数校验器

### 2. 寻找局部过滤
查看 API 入口到 Sink 之间是否存在：
- 参数类型强制转换（`Integer.parseInt()` 天然过滤非数字注入）
- 白名单校验（`if (!ALLOWED.contains(input)) throw ...`）
- 编码/转义（`StringEscapeUtils.escapeSql()`、`URLEncoder.encode()`）
- 路径规范化（`Path.normalize().startsWith(baseDir)`）

### 3. 实战对抗裁决
- 现有防御**能挡住** RedValidator 的 `poc_payload` → DEFENDED
- 现有防御**挡不住** → VULNERABLE，分析防御为何失效

## 输出规范

### DEFENDED
当判定漏洞已被防御时，输出以下 JSON：
```json
{
  "status": "DEFENDED",
  "vuln_type": "【逐字复制】",
  "entry_route": "复制",
  "filepath": "复制",
  "line_number": "复制",
  "call_chain": "复制",
  "suspicion_reason": "复制",
  "defense_analysis": "具体防御机制 + 代码行号引用"
}
```
禁止输出 `attack_vector` / `poc_payload` / `max_impact` / `mitigation_advice`。

### VULNERABLE - 必须写入 Markdown 报告
当判定漏洞存在时，**必须**将漏洞报告写入文件。

#### 文件输出路径
`{target_dir}/reports/vuln/{漏洞类型}_{task_id}.md`

**注意**：
- `{target_dir}` 为被审计项目的根目录
- 漏洞类型使用英文小写，多个单词用连字符（如 sql-injection、xss、path-traversal）
- task_id 中的 `/` 替换为 `_`
- 例如：`/home/project/reports/vuln/sql-injection_TASK-INIT-001_SINK_0.md`

**必须先创建目录**：
```bash
mkdir -p {target_dir}/reports/vuln
```

#### Markdown 报告内容模板

```markdown
# {漏洞类型} — {文件名}:{行号}

| 字段 | 值 |
|---|---|
| **CWE** | {CWE 编号} |
| **严重度** | {Critical/High/Medium/Low} |
| **入口路由** | {入口 API 路由} |
| **文件路径** | {完整文件路径} |

## 调用链
{调用链分析，每行一个节点，格式：- 类名.方法名(调用位置)}

## 漏洞描述
{发现过程、漏洞原理、为什么可利用}

## 攻击向量
{如何利用这个漏洞}

## PoC
```
{poc 代码}
```

## 最大影响
{漏洞被利用后的最大影响}
```

**重要**：
- **不需要包含修复建议**
- 报告文件写入后，在响应末尾输出以下 JSON 标记：
```json
{
  "status": "VULNERABLE",
  "report_written": "reports/vuln/{漏洞类型}_{task_id}.md"
}
```

## 绝对禁止
- 禁止修改 `vuln_type`
- 禁止同时输出 DEFENDED 和 VULNERABLE 专有字段
- 禁止以"教学/演示项目"作为 DEFENDED 理由

## 漏洞类型专项指导

按 `vuln_type` 查阅 `references/INDEX.md` 找到对应文档：
- SQL Injection / Command Injection / Code Injection / LDAP / XPath / Template Injection → `injection-family.md`
- Path Traversal / Zip Slip → `path-traversal-family.md`
- SSRF → `ssrf.md`
- XXE → `xxe.md`
- XSS → `xss.md`
- Unsafe Deserialization / Unsafe Reflection → `deserialization-reflection.md`
- IDOR / Authentication Bypass / Privilege Escalation → `authz-family.md`
- Open Redirect → `redirect-family.md`
- Hardcoded Credentials → `credentials-backdoor.md`
- Weak Cryptography → `crypto-family.md`
- Cookie / Trust Boundary → `cookie-trust-boundary.md`
- Sensitive Data in Log / URL → `info-disclosure.md`