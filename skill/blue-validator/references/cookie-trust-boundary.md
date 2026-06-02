# Cookie & Trust Boundary Family（Insecure Cookie / Trust Boundary Violation）

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
