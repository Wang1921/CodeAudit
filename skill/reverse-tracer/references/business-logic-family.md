# Business Logic Family（Mass Assignment / Workflow Bypass / Race Condition / Insufficient Anti-Automation）

## 四类区别

| 类型 | 核心问题 | 典型代码模式 |
|---|---|---|
| **Mass Assignment** | 字段绑定无白名单 | `@ModelAttribute User` / `ObjectMapper.readValue(json, User.class)` 含 isAdmin 字段 |
| **Workflow Bypass** | 业务状态机可跳步 | 未付款直接走"已发货"分支 |
| **Race Condition** | TOCTOU / 并发未加锁 | `existsByUsername` + `save` 之间被并发抢插 |
| **Insufficient Anti-Automation** | 爆破/撞库无限速 | 登录失败次数无统计、无验证码 |

## sink 模式速查

### Mass Assignment
- `@ModelAttribute SomeEntity entity` —— Spring 自动绑定 request params 到 Entity
- `@RequestBody SomeEntity entity` —— JSON 反序列化到 Entity
- `BeanUtils.copyProperties($SRC, $DST)` —— Apache commons-beanutils 全字段拷贝
- `BeanUtils.populate($DST, $MAP)` —— 同上
- `ObjectMapper.readValue($JSON, EntityClass.class)` —— Jackson 反序列化到 Entity
- `WebDataBinder $B` 无 `setAllowedFields/setDisallowedFields`

### Workflow Bypass
- 业务状态机方法（如 `order.markPaid()` / `workflow.advance()` / `state.transitionTo(...)`）
- 状态转换没有"前置状态"校验
- 业务标志（如 `order.setStatus("SHIPPED")`）可被直接 setter 调用

### Race Condition
- TOCTOU: `if (repo.existsBy(x)) repo.save(...)` —— 两步之间可被并发抢
- 余额扣减: `account.setBalance(account.getBalance() - amount)` 无 `@Transactional` / 无乐观锁
- 共享状态: Spring Bean (`@RestController` 默认 singleton) 含成员变量 `int[] guesses`，多线程并发改

### Insufficient Anti-Automation
- 登录接口无失败次数限制 / 无 CAPTCHA
- 密码重置链接生成无 rate limit
- 暴破检测：无 `triedAttempts.incr() + isLocked()` 调用
- API 接口无 `@RateLimiter` / Bucket4j / Resilience4j

## 数据流追溯重点

### Mass Assignment
1. 找 `@ModelAttribute/@RequestBody` 注解 + 绑定的类；
2. 看绑定的类**是否含敏感字段**：`isAdmin / role / balance / permissions / ownerId`；
3. 看 controller / Entity 是否有：
   - `@JsonIgnore` / `@JsonProperty(access=READ_ONLY)` 标记敏感字段
   - `@InitBinder + setAllowedFields/setDisallowedFields`
   - DTO 隔离层
4. 任一条件不满足 → VULNERABLE。

### Workflow Bypass
跨文件追读业务状态机的所有方法，看：
- 每个状态转换方法**前置**条件是否校验
- 是否有 `if (currentState != EXPECTED) throw ...`

### Race Condition
1. 找 sink 是 read-modify-write 序列 / `existsBy + save` 形态；
2. 看是否被 `@Transactional` 包裹 + isolation 级别足够；
3. 看是否用 `synchronized` / `ReentrantLock` / DB 行锁 / CAS / 乐观锁版本字段；
4. Spring Bean 成员变量 + `@RestController` 默认 singleton → 多线程不安全。

### Insufficient Anti-Automation
跨文件追读 sink 的调用方法体内：
- 是否调 `RateLimiter.acquire()` / `Bucket.tryConsume()` / `triedXxx.incr()`
- 是否有 IP 计数 / 用户失败次数计数

## 常见误判

- ❌ "用了 @RequestBody 是正常的 Spring 用法" —— 看是否绑定到含敏感字段的 Entity
- ❌ "并发是小概率问题" —— 攻击者可主动构造并发请求触发
- ❌ "前端有限速" —— 攻击者绕过前端直接调 API
- ❌ "教学项目"借口
- ❌ Quiz 答题端点的 `if (input.equals("Solution"))` 不算 Anti-Automation 真漏洞（即使没限速也仅泄露 quiz 答案）
