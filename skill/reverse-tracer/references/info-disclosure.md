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

## 常见误判

- ❌ "log.info(user.getId())" —— `getId()` 返回 Long，是非敏感元数据，DEFENDED 合理
- ❌ "log.info(list.size())" —— size 是 int 元数据，DEFENDED 合理
- ❌ "printStackTrace 只在 catch 里写过一次" —— 看是否进入响应体（如 `body(e.getMessage())`）才算可外泄
- ❌ "URL 里只是 sessionId 是必须" —— sessionId 在 URL 会被浏览器历史/refer header 泄露，应放 Cookie + HttpOnly
- ❌ "教学项目"借口
