# Credentials & Backdoor Family（Hardcoded Credentials / Hardcoded Backdoor）

## 区别

| | Hardcoded Credentials | Hardcoded Backdoor |
|---|---|---|
| 形态 | **变量赋值**层面 | **业务判定**层面 |
| 例子 | `String password = "admin123"` | `if (input.equals("admin123")) return success()` |
| 风险 | 被泄露后任意人可用 | 知道字面量即可绕过认证 |

## PoC 模板

| 类型 | 攻击思路 |
|---|---|
| Hardcoded JWT secret | 拿到源码 → 自签包含 `admin=true` claim 的 token |
| Hardcoded DB 密码 | 直接连数据库（如果数据库网络可达） |
| Hardcoded API key | 用该 key 调用第三方服务（如 Stripe / Twilio）造成账单 |
| Hardcoded Backdoor | 直接输入硬编码字面量登录获 admin |
| Fallback Backdoor | 触发 DB 失败（拒绝服务 / 网络隔离） + 输入 fallback 字面量 |
