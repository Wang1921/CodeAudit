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

## 常见误判

- ❌ "URL 包含 'example.com' 就是内部" —— `http://attacker.com/?fake=example.com` 包含子串
- ❌ "URL 以 'http://example.com' 开头" —— `http://example.com.attacker.com/` 同样开头
- ❌ "只允许 HTTP/HTTPS" —— 没拦截 `//evil.com`（protocol-relative）
- ❌ "用 Set.contains(host)" —— `host:8080` / `host@evil` 等绕过
- ❌ 单次 URL 解码 —— `https://safe.com%2540evil.com` 双重解码后变 `https://safe.com@evil.com`
- ❌ 看到 "// 检查内部域名" 注释 —— 看实际代码而非注释
