# XSS (Cross-Site Scripting, CWE-79)

## sink 模式速查

### Servlet API 直接输出
- `response.getWriter().print/println/write/append/format/printf($X)`
- `response.getOutputStream().print/println/write($X)`
- `PrintWriter/Writer $W; $W.print/println/write($X)` (持有 writer 变量)
- `ServletOutputStream $O; $O.print/println($X)`

### Spring MVC
- `Model/ModelMap.addAttribute($KEY, $X)` —— 关键看模板用 `th:text`（转义）还是 `th:utext`（不转义）
- `ResponseEntity.body($X)` —— 直接塞响应体

### Thymeleaf / JSP
- Thymeleaf `th:utext="${...}"` ⚠️ 不转义
- JSP `<%= ... %>` ⚠️ 不转义
- JSP EL `${...}`（容器版本不同有差异）

### 邮件 / 通知体
- `JavaMailSender.send(...)` 的 HTML 邮件正文含外部输入（属 Email Header Injection / Stored XSS）

## 数据流追溯重点

1. 找输出 sink；
2. 看输出内容来源：
   - `@RequestParam String input` 等直接入参
   - 数据库读取（Stored XSS）
   - 文件 / 缓存读取
3. 任一可控 + 无 HTML/JS 转义 → VULNERABLE。

## 常见误判

- ❌ "项目用 Thymeleaf 默认安全" —— 看具体属性，`th:utext` 不转义
- ❌ "Spring 自动转义" —— 仅 `Model.addAttribute` + Thymeleaf `th:text` 链路；直接 `ResponseEntity.body` 不转义
- ❌ "用户必须登录才能 XSS" —— Stored XSS 可被其他用户触发
- ❌ "数据来自数据库不是 HTTP" —— Stored XSS 入口在写入侧，读取侧仍需要输出编码
- ❌ "教学项目"借口
- ❌ `Model.addAttribute("comment", userInput)` 当 key 含 "html" 或 "raw" 字样时，模板大概率用 `th:utext`，更危险
