# Authorization Family（IDOR / Missing Authorization / Privilege Escalation / Authentication Bypass）

## 四类区别（务必精确区分）

| 类型 | 核心问题 | 典型代码模式 |
|---|---|---|
| **Missing Authorization** | 接口完全无鉴权 | 无 `@PreAuthorize` / 无 filter / 无 token 校验 |
| **Authentication Bypass** | 鉴权逻辑本身可绕 | JWT alg=none / token 解析错 / 密钥硬编码 |
| **Privilege Escalation** | 已登录但越权访问高权资源 | 普通用户调到 admin-only 接口 |
| **IDOR** | 路径/参数 id 直查 DB 无 ownership 校验 | `findById(externalId)` 不跟 `if (ownerId == currentUser)` |

⚠️ **混淆点**（v11/v12 实测反面教材）：
- "已认证用户可删除所有邮件" → **Missing Authorization**（接口没分细分权限）而非 Privilege Escalation
- "只对 tom 用户校验密码其他用户直接失败" → **Authentication Bypass / Logic Flaw** 而非 Privilege Escalation
- "split 验证缺陷绕过路径校验" → **IDOR** 或 **Authentication Bypass**（看具体是访问他人资源还是绕过鉴权）

## sink 模式速查

### Missing Authorization
- `@PostMapping/@GetMapping/...` 注解 + **无** `@PreAuthorize/@Secured/@RolesAllowed`
- 全局 SecurityFilterChain 未配置该路径
- `permitAll()` 对敏感路径

### Authentication Bypass
- `Jwts.parser().parse(token)` —— 没 `setSigningKey()`（可接受 alg=none）
- `Jwts.parser().setSigningKey(JWT_PASSWORD)` 其中 `JWT_PASSWORD` 硬编码
- ExpiredJwtException 异常处理里继续使用 token 内容（不校验签名）
- jku/kid header 可控（攻击者指定密钥源）
- `if (input.equals(expectedToken))` —— 时序攻击（应用 `MessageDigest.isEqual` 常量时间比较）

### Privilege Escalation
- `if (request.getHeader("X-Admin") != null)` —— 客户端可伪造头
- `if (params.contains("isAdmin=true"))` —— Mass Assignment 配合
- 角色判定逻辑漏判某分支

### IDOR
- `repo.findById(id)` 后直接返回，没 `if (entity.ownerId == currentUser)`
- `dao.load(userInput)` 后 `setOwner(...)` —— 写场景同样需 ownership 检查
- URL `/user/{id}/profile` 不验 `{id}` 是否本人

## 数据流追溯重点

### Missing Authorization
fast-path：看接口方法上**有/无**鉴权注解，看 SecurityConfig 是否配置该路径。

### Authentication Bypass
1. 找 JWT 解析逻辑；
2. 看：
   - 是否调 `setSigningKey()`
   - 是否用 `parseClaimsJws`（强制验签）而非 `parse`
   - signing key 是否硬编码
   - 是否拒绝 alg=none
   - jku/kid 是否从 token header 解析（攻击者可控）

### Privilege Escalation
1. 找权限决策点（`if user.role == ADMIN`）；
2. 看 role 字段来源（DB / token claim / 客户端 header）；
3. 客户端可控来源 → VULNERABLE。

### IDOR
1. 找 `findById/load/get/select` + id 参数；
2. 看 id 来源（`@PathVariable` / `@RequestParam`）；
3. 找返回前**有/无** ownership 校验：
   - `if (entity.getOwnerId() != currentUserId()) throw new ForbiddenException()`
   - 或在 SQL 层 `WHERE id=? AND ownerId=?`
4. 无 ownership 校验 → VULNERABLE。

## 常见误判

- ❌ "用户必须登录" 当成 Missing Authorization 的 DEFENDED 理由 —— 已登录用户仍可触发 IDOR / Privilege Escalation
- ❌ 看到 `@PreAuthorize("isAuthenticated()")` 就判 DEFENDED —— 这只是"登录"不是"授权"
- ❌ "拦截器有 token 校验" —— 看具体逻辑是否能绕过 alg=none / jku
- ❌ 把 Auth Bypass 错挂为 Missing Authorization（v11/v12 实测）：JWT 密钥硬编码导致 token 伪造 → 是 Auth Bypass 不是 Missing
- ❌ "教学项目"借口
