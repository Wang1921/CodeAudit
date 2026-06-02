# Info Disclosure Family（Stack Trace Exposure / Sensitive Data in Log / Sensitive Data in URL）

## sink 模式速查

### Stack Trace Exposure
- `e.printStackTrace()` —— 默认输出到 stderr，但 web 环境可能进日志
- `response.getWriter().println(e.getMessage())` / `println(e.toString())` —— 直接发给客户端
- `ResponseEntity.status(500).body(e.toString())` / `body(stackTrace)` —— 发给客户端
- Spring 默认错误页含 stack trace（未禁用 `server.error.include-stacktrace`）

### Sensitive Data in Log
- `log.info("user=" + user)` 用 user 类含敏感字段
- `log.info("password=" + password)` / `log.debug("token=" + jwt)`
- `logger.warn("query={}", sqlWithCredentials)`
- `log.error("login failed for {}", request)` —— request 可能含 Authorization 头

### Sensitive Data in URL
- `String url = "/redirect?token=" + jwt` —— token 在 URL 里
- `response.sendRedirect("/login?password=" + password)`
- 拼接到 URL query 的 password / api_key / secret / sessionId

## 数据流追溯重点

### Stack Trace Exposure
fast-path：看 `printStackTrace()` 调用或异常对象进入响应体。

### Sensitive Data in Log
1. 找 `log.xxx(...)` 调用；
2. 对每个非字面量参数：
   - 解析返回类型：是 `int / long / boolean / 枚举 / Duration / LocalDateTime` 等元数据 → 安全
   - 是 `String / Object` 且名称含 password / secret / token / key / credential → 危险
   - 是 entity 类的 toString → 看类定义是否有 `@ToString(exclude = {...})` 排除敏感字段
3. 任一参数携带敏感数据 → VULNERABLE。

### Sensitive Data in URL
看 URL 字符串拼接里是否有 password / token / apiKey / secret / sessionId 变量。

## 防御机制速查

### Stack Trace
- 全局异常处理器 `@ControllerAdvice` 统一返回 `{"error": "Internal Error"}` 不含细节
- Spring Boot `server.error.include-stacktrace=never` + `include-message=never`
- 日志框架 `MaskingPatternLayout` / `RewriteAppender` 过滤敏感正则
- 生产环境 `printStackTrace` 替换为 `log.error("msg", e)`（用日志框架而非 stderr）

### Sensitive Data in Log
- Lombok `@ToString(exclude = {"password", "secret", "token"})`
- Jackson `@JsonIgnore` 防 serialize
- 日志框架自定义 `Encoder` 过滤敏感字段
- 显式脱敏：`maskMiddle(creditCard, 4, 4)` / `"****" + token.substring(token.length()-4)`

### Sensitive Data in URL
- 敏感数据放 POST body / HTTP header，不放 URL query
- 用 short-lived token + 一次性 nonce

## 常见误判

- ❌ "log.info(user.getId())" —— `getId()` 返回 Long，是非敏感元数据，DEFENDED 合理
- ❌ "log.info(list.size())" —— size 是 int 元数据，DEFENDED 合理
- ❌ "printStackTrace 只在 catch 里写过一次" —— 看是否进入响应体（如 `body(e.getMessage())`）才算可外泄
- ❌ "URL 里只是 sessionId 是必须" —— sessionId 在 URL 会被浏览器历史/refer header 泄露，应放 Cookie + HttpOnly
- ❌ "教学项目"借口

## 证据引用范例

**DEFENDED 时**：
```
defense_analysis: "Line 28 log.info(\"user authenticated, id={}, role={}\",
                                    user.getId(), user.getRole());
                  — user.getId() 返回 Long,user.getRole() 返回 Role 枚举,
                  均为非敏感元数据.User 类定义 (UserEntity.java:15)
                  @ToString(exclude={\"passwordHash\",\"sessionToken\"}),
                  敏感字段已被 Lombok 排除."
```

**VULNERABLE 时**：
```
suspicion_reason: "Line 31 log.info(\"login admin with password: {}\", encodedPassword);
                  — encodedPassword 是 Base64 编码的密码(line 28),
                  Base64 是可逆编码不是哈希,泄露日志即等同泄露明文密码."
```

## PoC 模板

| 信息源 | 利用方式 |
|---|---|
| Stack trace 含 SQL 异常 | 看到 SQL 语句 + 表结构 → 精确构造后续注入 payload |
| Stack trace 含文件路径 | 推断项目结构 → 后续路径遍历 / 配置文件读取 |
| Log 含 JWT | 看日志 → 拿到 token 直接用 |
| Log 含 password 明文 | 直接用密码登录 |
| URL referer 泄露 | 用户从含 token 的 URL 点击外链 → token 泄露给第三方站 |
| 浏览器历史 | 用户共享设备 → 后人从历史 URL 中看到 token |
