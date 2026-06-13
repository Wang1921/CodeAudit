# Authorization Family（IDOR / Privilege Escalation / Authentication Bypass）

## 四类区别（务必精确区分）

| 类型 | 核心问题 | 典型代码模式 |
|---|---|---|
| **Authentication Bypass** | 鉴权逻辑本身可绕 | JWT alg=none / token 解析错 / 密钥硬编码 |
| **Privilege Escalation** | 已登录但越权访问高权资源 | 普通用户调到 admin-only 接口 |
| **IDOR** | 路径/参数 id 直查 DB 无资源归属校验（即未校验当前登录用户拥有该资源） | `findById(externalId)` 不跟 `if (ownerId == currentUser)` |

⚠️ **混淆点**（v11/v12 实测反面教材）：
- "只对 tom 用户校验密码其他用户直接失败" → **Authentication Bypass / Logic Flaw** 而非 Privilege Escalation
- "split 验证缺陷绕过路径校验" → **IDOR** 或 **Authentication Bypass**（看具体是访问他人资源还是绕过鉴权）

## 防御机制速查

### Authorization
- Spring Security: `@PreAuthorize("hasRole('ADMIN')")` / `@PostAuthorize("returnObject.ownerId == authentication.name")`
- Spring Security 全局: `http.authorizeHttpRequests().requestMatchers("/admin/**").hasRole("ADMIN")`
- 业务层: `@PostFilter("filterObject.ownerId == authentication.name")`

### Authentication
- JWT: 始终 `parseClaimsJws` + setSigningKey + 拒绝 alg=none + signing key 从配置中心
- 时序攻击防御: `MessageDigest.isEqual(a.getBytes(), b.getBytes())`
- 多因素认证 (MFA) 增加门槛

### IDOR
- Repository 方法签名带 ownerId: `findByIdAndOwnerId(id, currentUser)`
- 业务层强制资源归属校验: `if (!entity.getOwnerId().equals(currentUser)) throw ForbiddenException`
- 使用 UUID 而非自增 id（不防漏洞但提高猜测门槛）

## 常见误判

- ❌ 看到 `@PreAuthorize("isAuthenticated()")` 就判 DEFENDED —— 这只是"登录"不是"授权"
- ❌ "拦截器有 token 校验" —— 看具体逻辑是否能绕过 alg=none / jku
- ❌ "教学项目"借口

## 证据引用范例

**IDOR VULNERABLE 时**：
```
suspicion_reason: "Line 45 String authUserId = path.split(\"/\")[3];
                  Line 46 UserProfile profile = profileRepo.findById(authUserId);
                  Line 47 return profile;
                  — authUserId 来自 URL path 用户可控,findById 直接返回,
                  既无资源归属校验也无 @PreAuthorize,任意已登录用户可
                  通过传他人 id 读取他人 profile."
```

**Authentication Bypass VULNERABLE 时**：
```
suspicion_reason: "Line 55 private static final String JWT_PASSWORD =
                            TextCodec.BASE64.encode(\"victory\");
                  Line 139 Jwts.parser().setSigningKey(JWT_PASSWORD).parseClaimsJws(token);
                  — JWT_PASSWORD 解码后即 \"victory\" 字符串,硬编码于源码,
                  攻击者可伪造任意 claim 的 token,设 admin=true 实现身份伪造."
```
