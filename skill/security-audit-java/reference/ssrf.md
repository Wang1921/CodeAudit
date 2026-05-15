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

## 防御机制速查

### 主机白名单（最稳）
```java
URI uri = new URI(userInput).normalize();
String host = uri.getHost().toLowerCase();
if (!ALLOWED_HOSTS.contains(host)) throw new SecurityException();
// 或：
if (!host.endsWith(".example.com")) throw ...;
```

### 私有/保留段拦截
```java
InetAddress addr = InetAddress.getByName(uri.getHost());
if (addr.isLoopbackAddress() || addr.isSiteLocalAddress() ||
    addr.isLinkLocalAddress() || addr.isAnyLocalAddress()) throw ...;
```

需同时检查 IPv6（::1, fc00::/7, fe80::/10）+ 云元数据（169.254.169.254, fd00:ec2::254）。

### 协议白名单
```java
if (!"http".equalsIgnoreCase(uri.getScheme()) &&
    !"https".equalsIgnoreCase(uri.getScheme())) throw ...;
```
（禁 `file://`, `gopher://`, `dict://`, `jar://`, `ftp://`）

### 禁止 HTTP 重定向
RestTemplate / HttpClient 关闭 `followRedirects`，避免 302 跳到内网。

### 网络层隔离
应用通过独立"出网代理"出网，代理层做白名单 + 私有 IP 拦截（绕过应用层任何漏洞）。

## 常见误判

- ❌ "URL 包含 'webgoat' 子串就是内部" —— 攻击者构造 `http://attacker.com/?fake=webgoat`
- ❌ "URL 以 webgoat.local 开头就安全" —— 攻击者构造 `http://webgoat.local%2540evil.com`（双重解码）
- ❌ "Set.contains(host)" —— host 字符串若含端口（`host:8080`）会绕过
- ❌ 仅看 host 不检查 IP 解析 —— DNS rebinding 攻击：DNS 第一次返回内部 IP 第二次返回外部 IP
- ❌ "代码只创建 URI 对象不发请求" —— 看下游是否传给 HTTP client（LOW confidence 必查）

## 证据引用范例

**DEFENDED 时**：
```
defense_analysis: "Line 32 URI uri = new URI(userInput).normalize();
                  Line 33 String host = uri.getHost().toLowerCase();
                  Line 34 if (!ALLOWED_HOSTS.contains(host)) throw new SecurityException();
                  Line 36 InetAddress addr = InetAddress.getByName(host);
                  Line 37 if (addr.isLoopbackAddress() || addr.isSiteLocalAddress())
                            throw new SecurityException();
                  — 在 RestTemplate.exchange(uri, ...) 之前完整 host 白名单 + 私有 IP 拦截."
```

**VULNERABLE 时**：
```
suspicion_reason: "Line 57 String jku = (String) header.get(\"jku\");
                  Line 60 JwkProvider provider = new UrlJwkProvider(new URL(jku));
                  — jku 来自 JWT header (用户完全可控,见 line 54 token 来自 @RequestParam),
                  URL 直接构造 + UrlJwkProvider 会立即出站 HTTP GET 该 URL,
                  攻击者指向 http://169.254.169.254/ 可读 AWS 元数据."
```

## PoC 模板

| 目标 | poc_payload |
|---|---|
| 内网探测 | `http://10.0.0.1:8080/admin` / `http://127.0.0.1:6379/` (Redis) |
| AWS 元数据 | `http://169.254.169.254/latest/meta-data/iam/security-credentials/` |
| GCP 元数据 | `http://metadata.google.internal/computeMetadata/v1/` |
| Azure 元数据 | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` |
| 文件协议 | `file:///etc/passwd` (若 sink 支持 file://) |
| Gopher 打 Redis | `gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a` |
| 绕过白名单 | `http://example.com@evil.com/` / `http://example.com.evil.com/` |
| URL 双编码绕过 | `https://webgoat.local%2540evil.com` (%25=`%`,二次解码后 `@evil.com`) |
| DNS rebinding | 攻击者域名 DNS 第一次解析返回 1.1.1.1，第二次返回 127.0.0.1 |
