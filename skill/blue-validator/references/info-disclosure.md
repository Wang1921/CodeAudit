# Info Disclosure Family（Stack Trace Exposure / Sensitive Data in Log / Sensitive Data in URL）

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
