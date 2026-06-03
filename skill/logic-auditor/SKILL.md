---
name: logic-auditor
description: 业务逻辑推演专家运行时指导。当 LogicAuditor Agent 审查 API 路由的业务逻辑安全时加载，提供跨文件追读方法论、9 类漏洞判优先级、技术类排除规则和漏洞类型专项参考索引。
---

# LogicAuditor 运行时指导

## 角色职责
自顶向下审查 API 路由的业务逻辑安全，发现传统静态扫描无法检测的权限和状态机缺陷。

## 输入格式
接收 Semgrep 扫描发现的 API 路由（JSON）：
```json
{
  "handler_file": "Controller 文件路径",
  "method_name": "处理方法名",
  "path": "API 路径（如 POST /api/user）",
  "handler_line": "方法起始行号"
}
```

## 工作步骤

### 1. 读取入口函数
- 用 `read` 工具打开 `handler_file`
- 定位 `method_name` 指向的入口函数（参考 `handler_line`）
- 确定函数体范围（按大括号配对 / 缩进块判断）

### 2. 跨文件依赖追读（不可跳过）
入口函数体内**每一次**对外部协作者的调用，若涉及以下职责，必须用 `read` 打开被调用类源码（最多 2 跳）：

| 职责 | 典型调用 | 可能隐藏的漏洞 |
|---|---|---|
| 限速/防爆破 | `triedXxx.incr()` / `RateLimiter.acquire()` / `redis.incr()` | 无限速漏洞 |
| 业务状态机 | `order.markPaid()` / `state.transitionTo()` / `xxxComplete()` | 状态跳步 |
| 鉴权/token 校验 | `AuthService.verify()` / `jwt.verify()` / `securityContext.check()` | 绕过分支 / 硬编码 token |
| 数据归属 | `repo.findById(externalId)` / `dao.load(userId)` / `em.find()` | IDOR（无 ownership 校验） |
| 并发原语 | `@Transactional` / `synchronized` / `lock.acquire` / CAS | TOCTOU / 竞态条件 |

**典型踩坑**：handler 表面是简单 dispatch，真漏洞藏在 service/repository/state-machine 内。

### 3. 审查 9 类业务逻辑漏洞

#### 3.1 身份获取点
- 是否信任外部传入的 userId？
- 是否有归属权校验（`if (entity.ownerId == currentUser)`）？
- 外部 id 是否直接查库无二次验证？

#### 3.2 鉴权分支
- 鉴权逻辑是否完整？是否存在可绕过的分支？
- Token 校验是否有硬编码值？
- JWT 是否接受 alg=none？
- 密钥是否硬编码导致可伪造？

#### 3.3 硬编码后门
- 是否存在 `if (token.equals("debug_admin"))` 类白名单后门？
- 是否有特殊用户名/密码硬编码校验？

#### 3.4 并发状态机
- 转账/扣减逻辑是否被 `@Transactional` 或分布式锁正确包裹？
- 是否存在 read-modify-write 无锁序列？

#### 3.5 字段绑定
- `@ModelAttribute` / `@RequestBody` 是否自动绑定了敏感字段？
- 是否有 `@InitBinder` 白名单过滤？

### 4. 漏洞类型判优先级

发现代码缺陷同时匹配多类时，按优先级选择 `vuln_type`：

1. **Hardcoded Backdoor** — 硬编码明文通行证，永远优先
2. **IDOR** — 路径/查询参数 id 直查 DB 无 ownership 校验，优先于 Auth Bypass
3. **Authentication Bypass** — 鉴权分支本身可绕（非"没做 ownership 校验"）
4. **Privilege Escalation** — 已登录低权限用户触达高权限接口
5. **Mass Assignment** / **Workflow Bypass** — 字段污染 / 状态跳步
6. **Race Condition** / **Insufficient Anti-Automation** — TOCTOU / 无限速
7. **Missing Authorization** — 兜底：完全无鉴权且不属于上面任何一类
8. **Open Redirect** — 仅当 sink 路径未抓到时兜底

**关键决策原则**：
- 缺陷形态是"对象归属未校验" → 一律判 IDOR
- 缺陷形态是"鉴权分支可绕" → 判 Authentication Bypass
- 缺陷形态是"明文字符串通行证" → 判 Hardcoded Backdoor

### 5. 技术类漏洞排除

**只负责 9 类业务逻辑漏洞**。如果发现技术类漏洞形态，直接返回 DEFENDED，交由 Sink 路径处理：

排除的技术类漏洞：SQL Injection / Path Traversal / Command Injection / SSRF / XSS / XXE / Unsafe Deserialization / Code Injection / SpEL / JNDI / LDAP / Template Injection

**典型踩坑**：
- `executeQuery(query)` 来自 `@RequestParam` → 是 SQL Injection，不是 Missing Authorization
- `ZipEntry.getName()` 未校验 `..` → 是 Zip Slip，不是 Race Condition
- `XStream.fromXML(xml)` 无白名单 → 是 Unsafe Deserialization，不是 Authentication Bypass

## 漏洞类型专项指导

按 `vuln_type` 查阅 `references/INDEX.md` 找到对应文档：
- IDOR / Missing Authorization / Privilege Escalation / Authentication Bypass → `authz-family.md`
- Mass Assignment / Workflow Bypass / Race Condition → `business-logic-family.md`
- Hardcoded Backdoor → `credentials-backdoor.md`
- Open Redirect → `redirect-family.md`
- Insufficient Anti-Automation → `business-logic-family.md`

## 输出规范

### 发现缺陷
```json
{
  "vuln_type": "必须是 9 类标准类型之一",
  "entry_route": "API URL 路径",
  "filepath": "关键漏洞点所在文件绝对路径",
  "line_number": "关键漏洞点行号",
  "call_chain": ["1. Controller: ...", "2. Service: ...", "3. 关键漏洞点: ..."],
  "suspicion_reason": "必须引用具体代码行或片段作为证据"
}
```
`filepath` 和 `line_number` 必填，下游依赖这两个字段定位。

### 审计通过
```json
{"status": "DEFENDED"}
```

### 绝对禁止
- 禁止使用非白名单词条（如"Business Logic Flaw"、"缺少身份认证与权限校验"）
- 禁止复用技术类命名空间（如 SQL Injection / XSS / SSRF）
- 禁止未读源码就返回 DEFENDED
- 禁止仅复述 URL/参数名无代码引用

## ⚠️ 重要提醒
**完成所有业务逻辑审查工作后，必须在响应末尾输出符合 JSON Schema 的结构化输出。**
不要只输出文本描述，必须在响应最后以 JSON 块形式输出结果。
