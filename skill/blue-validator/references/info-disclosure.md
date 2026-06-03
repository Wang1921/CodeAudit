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

### 敏感信息判定规则（减少误报）

#### 1. 非敏感字段（可直接打印）
以下字段名即使出现在日志中也**不构成敏感信息泄露**：
- **用户标识**：userid, userId, uid, customerId, memberId, accountId, employeeId
- **缓存键**：redisKey, cacheKey, sessionKey, key (单叫 key 的)
- **ID 类元数据**：id, uuid, orderId, orderNo, transactionId, requestId, traceId
- **数量/统计类**：count, size, length, page, limit, offset
- **状态/枚举类**：status, state, type, category, level, priority
- **时间类**：createTime, updateTime, timestamp, expireTime
- **分页/排序类**：pageNum, pageSize, sortBy, orderBy
- **普通字符串**：name, title, description, message, content, body

#### 2. 对象打印需追溯实际值
当日志打印**对象本身**（而非对象的某个属性）时，BlueValidator 必须：
1. **回溯实参**：判断打印的是对象还是对象的属性
   - `log.info("user={}", user)` → 打印整个对象，需要进一步分析
   - `log.info("userId={}", user.getId())` → 打印属性，属性是 Long/String → **非敏感 → DEFENDED**
   - `log.info("pwd={}", user.getPassword())` → 打印凭据属性 → **VULNERABLE**
2. **追溯对象成员变量**：
   - 打开对象所属类定义（model/entity/dto/domain 包）
   - 检查 toString() 是否排除了敏感字段
   - 检查是否有 `@ToString(exclude = {"password", "token", ...})`
3. **特殊处理**：
   - 若对象是 SDK 自带类（如 `SnmpDevice`, `LdapContext`, `Jedis`）→ 默认含凭据，**VULNERABLE**
   - 若对象是自定义 Domain 且 toString 已脱敏 → **DEFENDED**

#### 3. 请求/响应对象不告警
以下场景因**无法确定是否含敏感信息**，统一判定为 **DEFENDED**：
- 打印 HTTP 请求对象：`log.info("request: {}", request)` / `log.info("req={}", httpRequest)`
- 打印 HTTP 响应对象：`log.info("response: {}", response)` / `log.info("resp={}", httpResponse)`
- 打印请求参数 Map：`log.info("params: {}", params)` / `log.info("args: {}", arguments)`
- 打印请求体：`log.info("body: {}", requestBody)` / `log.info("payload: {}", jsonBody)`
- 打印完整 API 返回：`log.info("api result: {}", apiResponse)`

**Why**：请求/响应可能含 Authorization header、Cookie、用户提交的表单数据等，
但 BlueValidator 没有完整的数据流追踪能力，无法确认是否真的有敏感信息。
这类告警应交给数据防泄露（DLP）系统或手动审计。

#### 4. 典型误判汇总表

| 场景 | 判定 | 理由 |
|------|------|------|
| `log.info("userId={}", userId)` | DEFENDED | userId 是纯数字 ID |
| `log.info("redis key: {}", redisKey)` | DEFENDED | redis key 是缓存键，非敏感 |
| `log.info("session key: {}", sessionKey)` | DEFENDED | session key 是缓存键，非敏感 |
| `log.info("user={}", user)` → User 类 toString 已脱敏 | DEFENDED | 类定义含敏感字段但 toString 已排除 |
| `log.info("user={}", user)` → User 类 toString 未脱敏 | VULNERABLE | toString 会打出 password/token |
| `log.info("request: {}", request)` | DEFENDED | 请求对象可能含敏感字段，无法确定 |
| `log.info("response: {}", response)` | DEFENDED | 响应对象可能含敏感字段，无法确定 |
| `log.info("params: {}", paramMap)` | DEFENDED | 参数 Map 可能含敏感字段，无法确定 |
| `log.info("API result: {}", apiResult)` | DEFENDED | API 返回值可能含敏感字段，无法确定 |

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
