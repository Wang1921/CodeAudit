# Info Disclosure Family（Stack Trace Exposure / Sensitive Data in Log / Sensitive Data in URL）

## PoC 模板

| 信息源 | 利用方式 |
|---|---|
| Stack trace 含 SQL 异常 | 看到 SQL 语句 + 表结构 → 精确构造后续注入 payload |
| Stack trace 含文件路径 | 推断项目结构 → 后续路径遍历 / 配置文件读取 |
| Log 含 JWT | 看日志 → 拿到 token 直接用 |
| Log 含 password 明文 | 直接用密码登录 |
| URL referer 泄露 | 用户从含 token 的 URL 点击外链 → token 泄露给第三方站 |
| 浏览器历史 | 用户共享设备 → 后人从历史 URL 中看到 token |
