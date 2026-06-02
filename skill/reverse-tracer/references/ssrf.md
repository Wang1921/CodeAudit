# SSRF (Server-Side Request Forgery, CWE-918)

## sink 模式速查（分两层 confidence）

### HIGH confidence — 真正"执行出站 HTTP"sink
- `new URL($X).openConnection()` / `URI.create($X).toURL().openConnection()` —— 链式开启连接
- `HttpRequest.newBuilder($URL)` / `$BUILDER.uri($URL)` —— JDK 11+ HttpClient
- `new HttpGet/HttpPost/HttpPut/HttpDelete/HttpHead/HttpPatch/HttpOptions($URL)` —— Apache HttpClient
- `$RT.getForObject/getForEntity/postForObject/postForEntity/exchange/put/delete/execute($URL, ...)` —— Spring RestTemplate
- `WebClient.create($URL)` —— Spring WebClient
- `$BUILDER.url($URL)` —— OkHttp
- `Jsoup.connect($URL)`
- `$AHC.prepareGet/preparePost/preparePut/prepareDelete($URL)` —— Apache AsyncHttpClient
- `$RETROFIT.baseUrl($URL)` —— Retrofit

### LOW confidence — 仅构造 URI/URL 对象（**需要污点链验证**）
- `new URL($X)` —— 单独构造，可能后续传给 HTTP client（VULNERABLE）也可能仅用作 URL 解析（DEFENDED）
- `URI.create($X)` / `new URI($X)`

⚠️ LOW confidence 必须看 sink 对象**后续是否传给 HTTP 客户端**：
- 传给 HttpClient/RestTemplate/openConnection → VULNERABLE
- 仅用于 `.getHost()` 做白名单校验 / 拼邮件链接 / 写 response.location 头 → DEFENDED

## 数据流追溯重点

1. 找 sink 调用（按上面两层分类）；
2. 看 URL 字符串来源：
   - `@RequestParam String url` 等直接入参
   - JWT header.jku / kid 字段（典型 JWT SSRF）
   - XML 外部实体（XXE → SSRF 链）
   - 文件 / DB 内容（间接污染）
3. URL 可控 + 无 host 白名单 → VULNERABLE。

## 常见误判

- ❌ "URL 包含 'webgoat' 子串就是内部" —— 攻击者构造 `http://attacker.com/?fake=webgoat`
- ❌ "URL 以 webgoat.local 开头就安全" —— 攻击者构造 `http://webgoat.local%2540evil.com`（双重解码）
- ❌ "Set.contains(host)" —— host 字符串若含端口（`host:8080`）会绕过
- ❌ 仅看 host 不检查 IP 解析 —— DNS rebinding 攻击：DNS 第一次返回内部 IP 第二次返回外部 IP
- ❌ "代码只创建 URI 对象不发请求" —— 看下游是否传给 HTTP client（LOW confidence 必查）
