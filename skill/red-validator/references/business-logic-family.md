# Business Logic Family（Mass Assignment / Workflow Bypass / Race Condition / Insufficient Anti-Automation）

## 四类区别

| 类型 | 核心问题 | 典型代码模式 |
|---|---|---|
| **Mass Assignment** | 字段绑定无白名单 | `@ModelAttribute User` / `ObjectMapper.readValue(json, User.class)` 含 isAdmin 字段 |
| **Workflow Bypass** | 业务状态机可跳步 | 未付款直接走"已发货"分支 |
| **Race Condition** | TOCTOU / 并发未加锁 | `existsByUsername` + `save` 之间被并发抢插 |
| **Insufficient Anti-Automation** | 爆破/撞库无限速 | 登录失败次数无统计、无验证码 |

## PoC 模板

| 类型 | 攻击思路 |
|---|---|
| Mass Assignment | POST `/user?username=hacker&isAdmin=true` 或 JSON 含 `{"isAdmin": true}` |
| Workflow Bypass | 跳过 `/payment` 直接 POST `/order/markPaid` |
| Race Condition (注册) | 用脚本并发 50 次 POST `/register?username=admin` |
| Race Condition (扣减) | 用脚本并发 100 次 POST `/transfer?amount=10` 余额 10 元的账户 |
| Anti-Automation (暴破) | 用脚本 1 秒发 1000 次 POST `/login?password=x` 跑字典 |
