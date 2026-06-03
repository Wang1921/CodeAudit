# Business Logic Family（/ Workflow Bypass / Race Condition / Insufficient Anti-Automation）

## 四类区别

| 类型 | 核心问题 | 典型代码模式 |
|---|---|---|
| (已删除) | 字段绑定无白名单 | `@ModelAttribute User` / `ObjectMapper.readValue(json, User.class)` 含 isAdmin 字段 |
| **Workflow Bypass** | 业务状态机可跳步 | 未付款直接走"已发货"分支 |
| **Race Condition** | TOCTOU / 并发未加锁 | `existsByUsername` + `save` 之间被并发抢插 |
| **Insufficient Anti-Automation** | 爆破/撞库无限速 | 登录失败次数无统计、无验证码 |

## 防御机制速查

### Mass Assignment
```java
@RestController
public class UserController {
  @InitBinder
  public void initBinder(WebDataBinder binder) {
    binder.setAllowedFields("username", "email", "password");
    // 或 binder.setDisallowedFields("id", "isAdmin", "role");
  }

  @PostMapping("/user")
  public User create(@ModelAttribute User user) { ... }
}
```
或用 DTO 隔离：
```java
@PostMapping("/user")
public User create(@RequestBody CreateUserDTO dto) {
  User user = new User();
  user.setUsername(dto.getUsername());
  // 手动映射,排除 isAdmin
  return userRepo.save(user);
}
```

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

**Mass Assignment VULNERABLE 时**：
```
suspicion_reason: "Line 25 ObjectMapper mapper = new ObjectMapper();
                  Line 26 return mapper.readValue(comment, Comment.class);
                  — Comment 类(Comment.java) 定义包含 user/dateTime/text 等字段,
                  ObjectMapper 默认绑定全部字段无白名单,
                  攻击者构造 JSON 含未公开字段(如 isOwner=true)即可注入."
```

**Race Condition VULNERABLE 时**：
```
suspicion_reason: "Line 42 if (userRepository.existsByUsername(username))
                            throw new UserAlreadyExistsException();
                  Line 43 userRepository.save(new User(username, password));
                  — line 42 检查 与 line 43 保存之间无 @Transactional + 无锁,
                  两个并发线程同时通过 existsBy 检查后都会执行 save,
                  导致同用户名重复创建多个记录."
```
