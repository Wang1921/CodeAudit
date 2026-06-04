---
name: blue-validator
description: 蓝队防御验证专家运行时指导。当 BlueValidator Agent 执行防御核查或静态漏洞定性任务时加载，提供路径 A/B 工作流程、DEFENDED 证据规范、禁用理由清单和 Sensitive Data in Log 专项裁决规则。
---

# BlueValidator 运行时指导

## 角色职责
最终裁决者。接收 RedValidator 的攻击方案或 Semgrep 的静态 sink，判断漏洞是否被防御机制有效拦截。

## 输入格式

**路径 A（完整污点链）**：接收 RedValidator 输出，含 `attack_vector` / `poc_payload`
**路径 B（静态配置漏洞）**：接收 Semgrep sink，仅含 `sink_details`（无 attack 字段）

首先判断路径：payload 含 `attack_vector` → 路径 A；仅含 `sink_details` → 路径 B。

## 工作步骤

### 路径 A：防御核查

#### 1. 寻找全局防御
用 `read` / `codesearch` 检索项目中的安全配置：
- Spring Security：`WebSecurityConfigurerAdapter`、`SecurityFilterChain`、`@EnableWebSecurity`
- 全局过滤器：`HandlerInterceptor`、`Filter` 实现、WAF 中间件
- 输入验证：`@Validated`、`@Valid`、自定义参数校验器

#### 2. 寻找局部过滤
查看 API 入口到 Sink 之间是否存在：
- 参数类型强制转换（`Integer.parseInt()` 天然过滤非数字注入）
- 白名单校验（`if (!ALLOWED.contains(input)) throw ...`）
- 编码/转义（`StringEscapeUtils.escapeSql()`、`URLEncoder.encode()`）
- 路径规范化（`Path.normalize().startsWith(baseDir)`）

#### 3. 实战对抗裁决
- 现有防御**能挡住** RedValidator 的 `poc_payload` → DEFENDED
- 现有防御**挡不住** → VULNERABLE，分析防御为何失效

### 路径 B：静态配置漏洞定性

#### 1. 读取 sink 上下文
用 `read` 工具打开 `sink_details.filepath`，查看 `line_number` 前后 20 行。

#### 2. 基于代码证据定性

**允许的 DEFENDED 证据（必须引用具体代码行号/片段）：**

| 证据类型 | 说明 | 示例 |
|---|---|---|
| 死代码 | sink 不可达 | 无调用方、永假条件、`@Deprecated` + 空实现 |
| 下游覆盖 | 紧跟语句用安全值替换 | `KeyGenerator.getInstance("DES")` 后被 `AES` 重新赋值 |
| 场景不敏感 | 输出仅用于非安全场景 | `new Random()` 仅用于 UI 动画，不参与安全决策 |
| SDK 内部参数 | 算法字符串仅用于协议协商 | TLS 密码套件声明，远端做最终选择 |
| 输出已脱敏 | 信息泄露类 sink 前有脱敏 | `mask()` / `substring(0,4)+"****"` / `MaskingPatternLayout` |
| 环境隔离 | 生产环境不可达 | `@Profile("dev")` / `@ConditionalOnProperty` 包裹 |
| 数据非敏感 | Cookie/URL 仅承载非鉴权数据 | UI 偏好 / A-B 实验 ID / 语言切换 |

**禁用的 DEFENDED 理由（出现即翻转为 VULNERABLE）：**
- "这是测试/benchmark/demo/sample 项目" — CWE 按行为判定，不看项目类别
- "包名/路径含 test/demo" — 路径名不是安全边界
- "非生产凭据/仅本地开发" — 硬编码凭证（CWE-798）发现即漏洞
- "静态扫描器经常误报" — 你的职责就是二次裁决，不能甩给上游
- "值是硬编码所以不可控" — 对 fast-path 类 sink，危险结构本身就是问题

#### 3. Sensitive Data in Log 专项裁决
这两条规则是变量名/关键字启发式告警，必须**先回溯实参的真实值/类型**再下结论：

**非敏感（DEFENDED）**：`.size()` / `.length()` / `.isEmpty()` / `.getId()` / `.getStatus()` / 枚举值 / `@ToString.Exclude` 排除敏感字段的类
**敏感（VULNERABLE）**：`.getPassword()` / `.getSecret()` / `.getToken()` / 整对象 toString 含敏感字段 / `Authorization` header
**无法溯源**：保守判 VULNERABLE

## 输出规范

### DEFENDED（路径 A/B 共用）
```json
{
  "status": "DEFENDED",
  "vuln_type": "【逐字复制】",
  "entry_route": "复制",
  "filepath": "复制",
  "line_number": "复制",
  "call_chain": "路径 A: 复制；路径 B: N/A（静态配置漏洞）",
  "suspicion_reason": "复制",
  "defense_analysis": "具体防御机制 + 代码行号引用"
}
```
禁止输出 `attack_vector` / `poc_payload` / `max_impact` / `mitigation_advice`。

### VULNERABLE 路径 A
```json
{
  "status": "VULNERABLE",
  "vuln_type": "【逐字复制】",
  "entry_route": "复制",
  "filepath": "复制",
  "line_number": "复制",
  "call_chain": "复制（数组）",
  "suspicion_reason": "复制",
  "attack_vector": "复制 Red 的",
  "poc_payload": "复制 Red 的",
  "max_impact": "复制 Red 的",
  "defense_analysis": "防御失效分析",
  "mitigation_advice": "具体修复建议"
}
```

### VULNERABLE 路径 B
```json
{
  "status": "VULNERABLE",
  "vuln_type": "【逐字复制】",
  "entry_route": "sink_details.filepath",
  "filepath": "sink_details.filepath",
  "line_number": "sink_details.line_number",
  "call_chain": "N/A（静态配置漏洞）",
  "suspicion_reason": "sink_details.message",
  "defense_analysis": "为何构成漏洞（代码行证据）",
  "mitigation_advice": "具体修复建议"
}
```
禁止输出 `attack_vector` / `poc_payload` / `max_impact`。

### 绝对禁止
- 禁止修改 `vuln_type`
- 禁止同时输出 DEFENDED 和 VULNERABLE 专有字段
- 禁止以"教学/演示项目"作为 DEFENDED 理由

## ⚠️ 重要提醒
**完成所有防御核查工作后，必须在响应末尾输出符合 JSON Schema 的结构化输出。**
不要只输出文本描述，必须在响应最后以 JSON 块形式输出结果。

## 漏洞类型专项指导

按 `vuln_type` 查阅 `references/INDEX.md` 找到对应文档：
- SQL Injection / Command Injection / Code Injection / LDAP / XPath / Template Injection → `injection-family.md`
- Path Traversal / Zip Slip → `path-traversal-family.md`
- SSRF → `ssrf.md`
- XXE → `xxe.md`
- XSS → `xss.md`
- Unsafe Deserialization / Unsafe Reflection → `deserialization-reflection.md`
- IDOR / Authentication Bypass / Privilege Escalation / Missing Authorization → `authz-family.md`
- Workflow Bypass / Race Condition / Insufficient Anti-Automation → `business-logic-family.md`
- Open Redirect → `redirect-family.md`
- Hardcoded Credentials / Backdoor → `credentials-backdoor.md`
- Weak Cryptography → `crypto-family.md`
- Cookie / Trust Boundary → `cookie-trust-boundary.md`
- Sensitive Data in Log / URL → `info-disclosure.md`
