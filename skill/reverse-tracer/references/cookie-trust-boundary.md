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

## 常见误判

- ❌ "项目用了 Spring Session" —— 看具体 Cookie 实现，仍需要 setSecure/setHttpOnly
- ❌ "Cookie 只装非敏感数据" —— 必须明确是 UI 偏好/语言切换才能放宽，session/auth/csrf 类 cookie 不可
- ❌ "测试环境不需要 Secure" —— 看是否有 `@Profile("test")` 隔离，否则生产环境同样易感
- ❌ "教学项目"借口
