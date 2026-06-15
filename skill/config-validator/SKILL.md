---
name: config-validator
description: 配置静态分析专家运行时指导。当 ConfigValidator Agent 分析 taint_required=false 的静态配置漏洞时加载，提供各类配置漏洞的静态定性方法和 DEFENDED 证据规范。
---

# ConfigValidator 运行时指导

## 角色职责
处理 Semgrep 扫描出的静态配置漏洞（taint_required=false），直接做静态定性判断，无需追踪调用链或构造攻击。

## 输入格式
接收 Semgrep sink 信息（JSON）：
```json
{
  "sink_details": {
    "vuln_class": "HardcodedCredentials",
    "filepath": "漏洞文件路径",
    "line_number": "行号",
    "message": "Semgrep 原始告警信息"
  }
}
```

## 工作步骤

### 1. 读取 sink 上下文
用 `codegraph` 工具打开 `sink_details.filepath`，结合上下文分析 sink 点的语义和用途。

### 2. 基于代码证据定性

**允许的 DEFENDED 证据（必须引用具体代码��号/片段）：**

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
- "非生产凭据/仅本地开发" — 硬编码凭证发现即漏洞
- "静态扫描器经常误报" — 你的职责就是二次裁决，不能甩给上游
- "值是硬编码所以不可控" — 对静态配置漏洞，危险结构本身就是问题

### 3. 按漏洞类型分析

#### Hardcoded Credentials
- 检查硬编码值是否被使用于安全决策（如 JWT 签名、数据库密码、API 密钥）
- 允许的 DEFENDED：死代码、环境隔离（@Profile("dev")）

#### Weak Cryptography / Static IV / Constant Salt
- 检查算法/IV/Salt 是否用于生产安全决策
- 允许的 DEFENDED：下游覆盖、场景不敏感

#### Sensitive Data in Log
**敏感信息强制性裁决标准（不得偏离）：**

仅以下 6 类字段为敏感信息，命中即判 VULNERABLE（除非有脱敏/排除）：
1. **密码**：password, passwd, pwd, credential等
2. **密钥**：secret, api_key, apikey, sk, ak, access_key, private_key等
3. **认证凭据**：token, auth, jwt, session_id, sessionid等
4. **手机号**：phone, mobile, tel, cellphone等
5. **邮箱**：email, mail等
6. **会话标识**：session_id, JSESSIONID, SID（特指 HTTP 会话的 session ID）等

**除上述 6 类外，全部为非敏感信息，直接判 DEFENDED。** 包括但不限于：
- userId, tenantId, username, name, nickname, accountId, orgId
- IP, deviceId, mac, host, port
- status, code, type, message, result, count, id, uuid

**禁止以 GDPR/隐私合规/数据保护等宽泛理由将非 6 类字段判定为敏感。**

**模式 A：显式访问**
- 检查返回类型：boolean 返回值方法（如 `isPasswordSet()`）是误报
- 检查脱敏处理：有 `MaskUtil.mask()` 等脱敏函数则判定为 FP

**模式 B：对象隐式打印**
- Lombok 检查：有 `@Data`/`@ToString` ���敏感字段无 `@ToString.Exclude` 是真阳性
- JSON 检查：有 `@JsonIgnore` 则判定为 FP
- 手动 toString：检查重写的 toString() 是否拼接敏感字段

**审计边界三原则：**
1. **所见即所得**：只评估日志语句显式打印的字段
2. **拒绝假设**：不假设未显示的代码会被执行
3. **字段提取即清洗**：提取非敏感字段（如 ID、name）视为清洗

## 输出规范

### VULNERABLE
```json
{
  "status": "VULNERABLE",
  "vuln_type": "【逐字复制 sink_details.vuln_class】",
  "entry_route": "sink_details.filepath",
  "filepath": "sink_details.filepath",
  "line_number": "sink_details.line_number",
  "call_chain": "N/A（静态配置漏洞）",
  "suspicion_reason": "sink_details.message",
  "defense_analysis": "为何构成漏洞（代码行证据）",
  "mitigation_advice": "具体修复建议"
}
```

### DEFENDED
```json
{
  "status": "DEFENDED",
  "vuln_type": "【逐字复制 sink_details.vuln_class】",
  "entry_route": "sink_details.filepath",
  "filepath": "sink_details.filepath",
  "line_number": "sink_details.line_number",
  "call_chain": "N/A（静态配置漏洞）",
  "suspicion_reason": "sink_details.message",
  "defense_analysis": "具体防御机制 + 代码行号引用"
}
```

## ⚠️ 重要提醒
- **完成所有分析工作后，必须在响应末尾输出符合 JSON Schema 的结构化输出**
- 禁止同时输出 DEFENDED 和 VULNERABLE 专有字段
- 禁止以"教学/演示项目"作为 DEFENDED 理由