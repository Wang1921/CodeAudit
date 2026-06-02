# Redirect Family（Open Redirect / Unvalidated Forward）

## 共性

应用根据外部参数做跳转或转发。攻击者控制目标 URL → 钓鱼 / 内网探测 / 二次攻击。

## sink 模式速查

### Open Redirect（302 跳转）
- `response.sendRedirect($URL)` —— Servlet API
- `return "redirect:" + $URL` —— Spring MVC（String 视图）
- `RedirectView($URL)` / `new RedirectView($URL).renderMergedOutputModel(...)`
- `ResponseEntity.status(302).header("Location", $URL).build()`
- `ModelAndView("redirect:" + $URL)` —— Spring MVC

### Unvalidated Forward（服务器内部转发）
- `request.getRequestDispatcher($PATH).forward(request, response)` —— 转到任意内部资源
- `return "forward:" + $PATH` —— Spring MVC

## 数据流追溯重点

1. 找跳转 / 转发 sink；
2. 看 URL/path 来源：
   - `@RequestParam String url` / `@RequestParam String returnTo`
   - 数据库读出的 URL（Stored Redirect）
3. 任一可控 + 无白名单 → VULNERABLE。

## 防御机制速查

### 主机白名单
```java
URI uri = new URI(userUrl).normalize();
String host = uri.getHost();
if (host == null || !ALLOWED_HOSTS.contains(host.toLowerCase()))
    throw new SecurityException();
response.sendRedirect(uri.toString());
```

### 仅允许相对路径
```java
if (userUrl.startsWith("/") && !userUrl.startsWith("//")) {
    // 相对路径,安全
} else throw ...;
```
⚠️ `//evil.com` 是 protocol-relative URL，浏览器会跳转到 evil.com，**必须**检查 `//` 开头。

### Forward 路径白名单
```java
if (!ALLOWED_FORWARD_PATHS.contains(path)) throw ...;
```

### 完全禁用动态跳转
推荐做法：用户登录后跳转到固定的 dashboard，不接受 returnTo 参数。

## 常见误判

- ❌ "URL 包含 'example.com' 就是内部" —— `http://attacker.com/?fake=example.com` 包含子串
- ❌ "URL 以 'http://example.com' 开头" —— `http://example.com.attacker.com/` 同样开头
- ❌ "只允许 HTTP/HTTPS" —— 没拦截 `//evil.com`（protocol-relative）
- ❌ "用 Set.contains(host)" —— `host:8080` / `host@evil` 等绕过
- ❌ 单次 URL 解码 —— `https://safe.com%2540evil.com` 双重解码后变 `https://safe.com@evil.com`
- ❌ 看到 "// 检查内部域名" 注释 —— 看实际代码而非注释

## 证据引用范例

**DEFENDED 时**：
```
defense_analysis: "Line 45 if (!userUrl.startsWith(\"/\") || userUrl.startsWith(\"//\"))
                          throw new SecurityException();
                  — 仅允许相对路径(/path),拒绝 //evil 形式的 protocol-relative URL,
                  攻击者无法跳转到外部域名."
```

**VULNERABLE 时**：
```
suspicion_reason: "Line 21 return \"redirect:\" + url;
                  — url 来自 @RequestParam (line 18),未做任何 host 校验,
                  攻击者输入 url=https://evil.com/phishing 即可被钓鱼."
```

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
