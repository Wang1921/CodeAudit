# XSS (Cross-Site Scripting, CWE-79)

## 防御机制速查

### 输出编码（按上下文）
```java
// HTML 元素内容
Encode.forHtml(input)               // OWASP Java Encoder
StringEscapeUtils.escapeHtml4(input) // Apache Commons Text
// HTML 属性值（双引号内）
Encode.forHtmlAttribute(input)
// JavaScript 字符串
Encode.forJavaScript(input)
// CSS 值
Encode.forCssString(input)
// URL 参数
Encode.forUriComponent(input)
```

### 模板引擎默认转义
- Thymeleaf `th:text` —— **默认转义**（安全），看到 `th:utext` 才报警
- Velocity `$!{...}` —— 默认不转义，必须包 `$esc.html(...)`
- FreeMarker `?html` filter，或全局 `output_format=HTMLOutputFormat`

### 内容安全策略（CSP）
```
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-xxx'
```

### 输入侧（不可靠）
- DOMPurify / OWASP Java HTML Sanitizer（仅富文本编辑器场景，普通输入应输出编码）

## 常见误判

- ❌ "项目用 Thymeleaf 默认安全" —— 看具体属性，`th:utext` 不转义
- ❌ "Spring 自动转义" —— 仅 `Model.addAttribute` + Thymeleaf `th:text` 链路；直接 `ResponseEntity.body` 不转义
- ❌ "用户必须登录才能 XSS" —— Stored XSS 可被其他用户触发
- ❌ "数据来自数据库不是 HTTP" —— Stored XSS 入口在写入侧，读取侧仍需要输出编码
- ❌ "教学项目"借口
- ❌ `Model.addAttribute("comment", userInput)` 当 key 含 "html" 或 "raw" 字样时，模板大概率用 `th:utext`，更危险

## 证据引用范例

**DEFENDED 时**：
```
defense_analysis: "Line 56 response.getWriter().write(Encode.forHtml(userComment));
                  — OWASP Java Encoder 对 HTML 上下文做编码,
                  < / > / & / \" / ' 等元字符都被转为实体引用."
```

**VULNERABLE 时**：
```
suspicion_reason: "Line 35 model.addAttribute(\"htmlContent\", commentBody);
                  且模板 comment.html line 12 使用 th:utext=\"\${htmlContent}\" 渲染原始 HTML.
                  commentBody 来自 @RequestParam (line 22),未经任何 HTML 转义,
                  可注入 <script>alert(document.cookie)</script>."
```
