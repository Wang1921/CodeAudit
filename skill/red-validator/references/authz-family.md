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

## 误判案例

| 防御手段 | 误判场景 | 为什么安全 |
|---|---|---|
| 资源归属校验 | `if (order.getOwnerId().equals(currentUserId))` | 查询结果与当前用户绑定，无法访问他人资源 |
| RBAC 注解 | `@PreAuthorize("hasRole('ADMIN')")` | 框架级鉴权拦截，非 ADMIN 返回 403 |
| 接口级权限矩阵 | `if (!user.getPermissions().contains(requiredPerm)) throw ...` | 显式权限检查，无权限直接拒绝 |
| UUID 替代自增 ID | 使用不可预测的 UUID 作为资源标识 | 攻击者无法枚举其他资源的 ID |
| JWT 签名验证 | `Jwts.parser().setSigningKey(key).parseClaimsJws(token)` | 篡改 token 签名验证失败 |
| Spring Security 过滤链 | `httpSecurity.authorizeRequests().anyRequest().authenticated()` | 所有请求必须认证，未登录返回 401 |
| 多步鉴权 | 先校验 token 有效性，再校验资源归属 | 双重校验，任一失败即拒绝 |

## 绕过案例

| 看似防御 | 绕过思路 | 示例 |
|---|---|---|
| JWT alg=none | 服务器未强制校验算法 | 修改 header `{"alg":"none"}` + 删除签名 → 伪造任意 claim |
| JWT 密钥硬编码 | 源码泄露即可签发 token | 拿到 `secret="mySecret123"` → 自签 `admin=true` claim |
| JWT jku/x5u 头 | 服务器从外部 URL 拉取公钥 | header 加 `"jku":"http://attacker/jwk.json"` 用自己的公钥签名 |
| JWT 未校验 issuer/audience | 接受任意来源的合法签名 token | 用 A 服务的合法 token 访问 B 服务（跨服务复用） |
| 只校验用户是否登录不校验资源归属 | `findById(id)` 不检查 owner | 修改 URL `/user/123/profile` → `/user/124/profile` 访问他人数据 |
| 自增 ID 做资源标识 | 枚举 ID | `/api/order/1001` → `/api/order/1002` 遍历所有订单 |
| 权限校验在 Controller 但绕过路由 | `/admin/users` 被 Spring 拦截，但 `/api/admin/users` 未配置 | 路径变体绕过安全配置 |
| 权限校验在前端 | 后端无鉴权 | 修改请求绕过前端 JS 校验直接调 API |
| 分级权限只拦截 HTTP 方法 | GET 放行但 POST 需要权限 | 用 GET 代替 POST 或用 PUT/PATCH 绕过方法级鉴权 |
| 降级认证逻辑 | fallback 路径跳过鉴权 | DB 连接失败 → fallback 到硬编码用户 → 认证绕过 |
| `equals()` 而非 `equalsIgnoreCase()` | 大小写绕过 | 用户名 `Admin` vs `admin` — 比较不严格导致绕过 |
| split / substring 解析路径校验缺陷 | 路径中加特殊字符 | `/admin;;/users` — 某些框架 normalize 后变成 `/admin/users` 但校验时匹配不到 |
