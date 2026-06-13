# Authorization Family（IDOR / Privilege Escalation / Authentication Bypass）

## 四类区别（务必精确区分）

| 类型 | 核心问题 | 典型代码模式 |
|---|---|---|
| **Authentication Bypass** | 鉴权逻辑本身可绕 | JWT alg=none / token 解析错 / 密钥硬编码 |
| **Privilege Escalation** | 已登录但越权访问高权资源 | 普通用户调到 admin-only 接口 |
| **IDOR** | 路径/参数 id 直查 DB 无资源归属校验（即未校验当前登录用户拥有该资源） | `findById(externalId)` 不跟 `if (ownerId == currentUser)` |

⚠️ **混淆点**（v11/v12 实测反面教材）：
- "只对 tom 用户校验密码其他用户直接失败" → **Authentication Bypass / Logic Flaw** 而非 Privilege Escalation
- "split 验证缺陷绕过路径校验" → **IDOR** 或 **Authentication Bypass**（看具体是访问他人资源还是绕过鉴权）

## PoC 模板

| 类型 | 攻击思路 |
|---|---|
| IDOR | 把 URL `/user/123/profile` 改成 `/user/124/profile`，看是否能读他人数据 |
| Missing Auth | 不带 cookie/token 直接请求敏感接口，看是否返回 200 |
| Privilege Escalation | 普通用户调 `/admin/users` 看是否返回数据 |
| JWT alg=none | header 改 `{"alg":"none"}` + 删 signature 后发请求 |
| JWT 密钥硬编码 | 拿到源码 → 自签 `admin=true` claim 的 token |
| JWT jku 注入 | header 加 `"jku":"http://attacker/jwk.json"` 自己提供公钥 |
