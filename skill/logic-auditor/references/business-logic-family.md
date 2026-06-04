# Business Logic Family（/ Workflow Bypass / Race Condition / Insufficient Anti-Automation）

## 四类区别

| 类型 | 核心问题 | 典型代码模式 |
|---|---|---|
| (已删除) | 字段绑定无白名单 | `@ModelAttribute User` / `ObjectMapper.readValue(json, User.class)` 含 isAdmin 字段 |
| **Workflow Bypass** | 业务状态机可跳步 | 未付款直接走"已发货"分支 |
| **Race Condition** | TOCTOU / 并发未加锁 | `existsByUsername` + `save` 之间被并发抢插 |
| **Insufficient Anti-Automation** | 爆破/撞库无限速 | 登录失败次数无统计、无验证码 |

## sink 模式速查

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

## 防御机制速查

### Workflow
状态机方法前置校验：
```java
public void markPaid() {
  if (this.status != Status.PENDING_PAYMENT)
    throw new IllegalStateException();
  this.status = Status.PAID;
}
```

### Race Condition
```java
@Transactional(isolation = Isolation.SERIALIZABLE)
public void register(String username) {
  if (repo.existsByUsername(username)) throw ...;
  repo.save(new User(username));
}
// 或用乐观锁:
@Version
private Long version;
```

### Anti-Automation
```java
// Bucket4j
if (!bucket.tryConsume(1)) throw new RateLimitedException();
// 或 Resilience4j
RateLimiter limiter = RateLimiter.ofDefaults("login");
return limiter.executeSupplier(() -> doLogin(...));
// 或自实现:
if (loginAttempts.get(username) > 5) throw new LockedException();
```

## 常见误判

- ❌ "用了 @RequestBody 是正常的 Spring 用法" —— 看是否绑定到含敏感字段的 Entity
- ❌ "并发是小概率问题" —— 攻击者可主动构造并发请求触发
- ❌ "前端有限速" —— 攻击者绕过前端直接调 API
- ❌ "教学项目"借口
- ❌ Quiz 答题端点的 `if (input.equals("Solution"))` 不算 Anti-Automation 真漏洞（即使没限速也仅泄露 quiz 答案）

## 证据引用范例

**Race Condition VULNERABLE 时**：
```
suspicion_reason: "Line 42 if (userRepository.existsByUsername(username))
                            throw new UserAlreadyExistsException();
                  Line 43 userRepository.save(new User(username, password));
                  — line 42 检查 与 line 43 保存之间无 @Transactional + 无锁,
                  两个并发线程同时通过 existsBy 检查后都会执行 save,
                  导致同用户名重复创建多个记录."
```

## PoC 模板

| 类型 | 攻击思路 |
|---|---|
| Workflow Bypass | 跳过 `/payment` 直接 POST `/order/markPaid` |
| Race Condition (注册) | 用脚本并发 50 次 POST `/register?username=admin` |
| Race Condition (扣减) | 用脚本并发 100 次 POST `/transfer?amount=10` 余额 10 元的账户 |
| Anti-Automation (暴破) | 用脚本 1 秒发 1000 次 POST `/login?password=x` 跑字典 |
