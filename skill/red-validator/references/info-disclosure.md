# Info Disclosure Family（Stack Trace Exposure / Sensitive Data in Log / Sensitive Data in URL）

## 误判案例

| 防御手段 | 误判场景 | 为什么安全 |
|---|---|---|
| 全局异常处理器 | `@ControllerAdvice` 返回通用错误 JSON | Stack trace 不返回客户端，只记内部日志 |
| 日志脱敏 | `log.info("user={}", mask(phone))` → `138****1234` | 敏感字段脱敏后无法还原 |
| Token 仅存 Cookie/Body | 不在 URL 中传递敏感信息 | 浏览器历史 / Referer 不会泄露 |
| `server.error.include-stacktrace=never` | Spring Boot 生产配置禁止 stack trace | 异常时只返回通用 500 响应 |
| 日志级别控制 | 生产环境 INFO 级别，不输出 DEBUG 详情 | 敏感调试信息不被记录 |
| HTTPS 全站 | 所有请求走 TLS | URL 路径和参数在传输中加密，中间人无法嗅探 |
| POST 传敏感参数 | 敏感数据在请求体而非 URL | 请求体不进入浏览器历史 / Referer / 代理日志 |

## 绕过案例

| 看似防御 | 绕过思路 | 示例 |
|---|---|---|
| Stack trace 默认关闭但特定异常漏出 | 未被全局处理器捕获的异常类型 | 框架异常（如 Spring DispatcherServlet 404）仍返回详细堆栈 |
| Stack trace 在 500 页面隐藏但在 JSON 错误响应中 | 不同 Content-Type 响应不同 | `Accept: text/html` → 通用页面；`Accept: application/json` → 含 stack trace |
| 日志脱敏但规则不完整 | 新增字段未纳入脱敏 | 手机号脱敏但身份证号未脱敏 → 日志中可见完整 ID |
| 日志脱敏但异常对象仍含原始值 | `log.error("failed", exception)` | exception.getMessage() 含原始密码，脱敏只处理了参数 |
| 敏感数据不在 URL 但在 Referer 中泄露 | 从含 token 的页面跳转外链 | 用户从 `?token=xxx` 页面点外链 → Referer 头带 token 发给第三方 |
| Token 在 POST body 但服务端重定向到 GET | 302 重定向时拼入 URL | POST `/login` → 302 `Location: /dashboard?token=xxx` — token 进入 URL |
| Stack trace 关闭但错误信息含 SQL | 自定义错误消息泄露查询细节 | `"Duplicate entry 'admin' for key 'username'"` — 暴露表结构和数据 |
| 日志中 JWT 明文 | 审计日志记录请求头 | `Authorization: Bearer eyJ...` — 日志中可提取 token |
| URL 路径参数泄露 | `/api/user/john.doe@email.com/profile` | 邮箱在 URL 中 → 浏览器历史 / 代理日志 / Referer 泄露 |
| 敏感数据在 URL fragment | 部分场景 fragment 仍泄露 | SPA 路由 `#/token=xxx` — 某些 JS 库将 fragment 发往统计服务 |
