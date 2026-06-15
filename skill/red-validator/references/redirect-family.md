# Redirect Family（Open Redirect / Unvalidated Forward）

## 共性

应用根据外部参数做跳转或转发。攻击者控制目标 URL → 钓鱼 / 内网探测 / 二次攻击。

## 误判案例

| 防御手段 | 误判场景 | 为什么安全 |
|---|---|---|
| URL 白名单 | `if (!ALLOWED_DOMAINS.contains(host)) throw ...` | 只允许预定义域名，外部 URL 无法通过 |
| 相对路径跳转 | `redirect:/dashboard` — 不接受绝对 URL | 攻击者无法指定外部域名 |
| 框架内置校验 | Spring `redirect:` 前缀仅允许同源 | 框架级别阻断外部跳转 |
| 正则匹配域名 | `url.matches("^https://[a-z]+\\.example\\.com/.*")` | 严格正则限制子域和路径 |
| 禁止 URL 参数做跳转 | 跳转目标硬编码在代码中 | 外部输入不影响跳转地址 |
| Forward 路径白名单 | `if (!ALLOWED_PATHS.contains(path)) throw ...` | 只允许预定义内部路径 |

## 绕过案例

| 看似防御 | 绕过思路 | 示例 |
|---|---|---|
| 白名单子串匹配 | `url.contains("safedomain.com")` | `https://attacker.com/?safe=safedomain.com` — 子串匹配通过 |
| 白名单前缀匹配 | `url.startsWith("https://safedomain.com")` | `https://safedomain.com@evil.com/` — `@` 后才是真实主机 |
| 白名单域名但允许子域 | 攻击者控制子域 | `https://evil.safedomain.com/` — DNS 解析到攻击者 |
| Protocol-relative URL | `//evil.com/phishing` | 浏览器解释为 `https://evil.com/phishing` |
| URL 双重编码 | WAF / 过滤器只解码一次 | `https%3A%2F%2Fsafe.com%2540evil.com` → 二次解码后 `https://safe.com@evil.com` |
| `\r\n` CRLF 注入 | 在 URL 参数中注入换行 | `url=/safe%0d%0aSet-Cookie:%20evil=hacked` — 注入额外 HTTP 头 |
| Unvalidated Forward | 跳转校验但 Forward 无校验 | `path=/WEB-INF/web.xml` / `path=/admin/internal-only.jsp` — 服务端内部访问 |
| Data URI | `data:text/html,<script>alert(1)</script>` | 部分浏览器支持 data: 作为跳转目标 |
| JavaScript scheme | `javascript:alert(1)` | `href` 等 sink 中 JS scheme 可执行代码 |
| URL fragment 欺骗 | `https://safedomain.com#@evil.com` | 部分校验只看 `#` 前的部分，浏览器忽略 fragment |
| 反斜杠替代正斜杠 | `https://safedomain.com\\@evil.com` | 某些解析器将 `\` 当作 `/` 处理 |
| 白名单但允许 http + https | HTTPS 白名单被 http 降级 | `http://safedomain.com` — 无 TLS，中间人可劫持 |
