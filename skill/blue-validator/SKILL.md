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
用 `codegraph` 检索项目中的安全配置：
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
用 `codegraph` 工具打开 `sink_details.filepath`，查看 `line_number` 前后 20 行。

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
这条规则是变量名/关键字启发式告警，必须**先回溯实参的真实值/类型**再下结论：
**敏感信息定义（仅以下 6 类）：**
- **密码**：password, passwd, pwd, credential
- **密钥**：secret, api_key, apikey, sk, ak, access_key, private_key
- **认证凭据**：token, auth, jwt, session_id, sessionid
- **手机号**：phone, mobile, tel, cellphone
- **邮箱**：email, mail
- **会话标识**：session_id, JSESSIONID, SID（特指 HTTP 会话的 session ID）

**除上述 6 类外，其他都是非敏感信息**（如 userId、username、name、status、IP 等）。
##### 模式 A：显式访问 (Explicit Access)
       **场景**：日志中直接调用了方法或字段，例如 `log.info("pwd: " + user.getPassword())` 或 `log.info(config.secretKey)`.
       1.  **检查返回类型 (Type Check)**：
           * **误报**：如果调用的是返回 **boolean** 的方法（如 `isPasswordSet()`, `checkPassword()`）或返回 **int/long** 的长度方法（如 `getPasswordLength()`）。
           * **风险**：如果调用的是 Getter（如 `getPassword()`, `getAk()`）且返回类型是 String/CharSequence。
       2.  **检查脱敏处理 (Sanitization)**：
           * 检查日志语句中是否包裹了脱敏函数，如 `MaskUtil.mask(user.getPwd())` 或 `Desensitization.all(secret)`。
           * 如果有脱敏处理，视为 **False Positive**。
##### 模式 B：对象隐式打印 (Implicit Object Printing)
       **场景**：日志打印整个对象，例如 `log.info("User: {}", userDto)`。
       1.  **Lombok 检查 (关键)**：
           * 查看类定义是否有 `@Data`, `@ToString`, `@Value` 注解。
           * **真阳性 (True Positive)**：有上述注解，且敏感字段（如 `password`）**没有**标记 `@ToString.Exclude`。
           * **误报 (False Positive)**：敏感字段上有 `@ToString.Exclude`。
       2.  **JSON/序列化检查**：
           * 如果日志使用了 JSON 工具（如 `JSON.toJSONString(user)`）：
           * 检查敏感字段是否有 `@JsonIgnore` (Jackson), `@JSONField(serialize=false)` (Fastjson) 或 `transient` 关键字。如果没有忽略，视为风险。
       3.  **手动 toString 检查**：
           * 检查类中显式重写的 `toString()` 方法。
           * 确认该方法内部是否拼接了敏感字段（如 `return "pwd=" + password`）。
       # Audit Boundary & Scope (审计边界与范围 - 极其重要)
       请严格遵守以下分析边界，**严禁**对未显示的代码进行假设：
       1.  **所见即所得 (What You See Is What You Get)**：
            * **你的唯一职责**是分析该日志语句**最终输出了什么**。
            * **规则**：如果代码显式调用了 Getter 方法提取字段（如 `log.info(obj.getStorageId())`），你必须**只评估该字段**（`storageId`）的敏感性。
            * **禁止**因为 `obj` 本身包含敏感字段（如 `obj.password`）就认为 `obj.getStorageId()` 是不安全的。如果日志没有打印整个 `obj`，则忽略 `obj` 中的其他字段。
       2.  **拒绝假设 (No Speculation)**：
            * 不要假设“RestParam 对象可能在调用链的其他地方被打印”。如果提供的代码片段中没有显示，就视为没有发生。
            * 不要假设“toString() 方法可能被隐藏调用”，除非日志语句确实传入了对象引用（如 `log.info("param: {}", param)`）。如果传入的是 `param.getId()`，则绝不会触发 `param.toString()`。
       3.  **字段提取即清洗 (Field Extraction is Sanitization)**：
            * 从敏感对象中提取非敏感字段（如 ID, Status, Name, IP）的操作，视为一种“清洗”或“过滤”。此时判定为 **False Positive (FP)**。

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
- IDOR / Authentication Bypass / Privilege Escalation → `authz-family.md`
- Workflow Bypass / Race Condition / Insufficient Anti-Automation → `business-logic-family.md`
- Open Redirect → `redirect-family.md`
- Hardcoded Credentials → `credentials-backdoor.md`
- Weak Cryptography → `crypto-family.md`
- Cookie / Trust Boundary → `cookie-trust-boundary.md`
- Sensitive Data in Log / URL → `info-disclosure.md`
