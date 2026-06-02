# Credentials & Backdoor Family（Hardcoded Credentials / Hardcoded Backdoor）

## 区别

| | Hardcoded Credentials | Hardcoded Backdoor |
|---|---|---|
| 形态 | **变量赋值**层面 | **业务判定**层面 |
| 例子 | `String password = "admin123"` | `if (input.equals("admin123")) return success()` |
| 风险 | 被泄露后任意人可用 | 知道字面量即可绕过认证 |

## 防御机制速查

### Credentials
- 凭据从配置中心（Vault / Consul / AWS Secrets Manager）拉取
- 环境变量 `@Value("${DB_PASSWORD}")` + 部署时注入
- 密码哈希：BCrypt / Argon2，且加 salt
- 不要把密钥写在源码 / Git 仓库 / 镜像层里

### Backdoor
- 业务白名单值放配置中心 + 加密存储
- 测试凭证用临时账号 + 短过期时间 + 仅 dev 环境激活
- code review 强制人工审查所有 `if (input.equals("..."))` 模式

## 常见误判

- ❌ "密码看起来像占位符 'CHANGE_ME'" —— 仍是 Hardcoded Credentials，提示开发者修但代码本身就是漏洞
- ❌ "if 里只是 quiz 答案校验" —— 看上下文，是否真的用于鉴权 / 提权决策；quiz 答题端点的 `equals("Solution 4")` 非后门
- ❌ "代码注释说仅 dev 环境" —— 注释不可信，看是否有 `@Profile("dev")` / 环境检查代码
- ❌ "字面量是从常量类引入的" —— `if (input.equals(Constants.ADMIN_KEY))` 仍是后门，Constants.ADMIN_KEY 也是硬编码

## 证据引用范例

**Hardcoded Credentials VULNERABLE 时**：
```
suspicion_reason: "Line 45 private static final String JWT_SECRET = \"victory\";
                  Line 56 Jwts.builder().signWith(SignatureAlgorithm.HS256,
                                                  Base64.encode(JWT_SECRET));
                  — JWT 签名密钥硬编码为字面量 \"victory\",任何拿到源码的攻击者
                  可签发任意 admin claim 的 token."
```

**Hardcoded Backdoor VULNERABLE 时**：
```
suspicion_reason: "Line 21 if (\"CaptainJack\".equals(username) &&
                            \"BlackPearl\".equals(password)) {
                  Line 22     return success(this).build();
                  Line 23 }
                  — 硬编码用户名密码对比,任何知道 CaptainJack/BlackPearl 的
                  攻击者均可成功登录,等同于通用后门."
```

**fallback 后门**（v12 baseline 实测 SqlInjectionLesson6b）：
```
suspicion_reason: "Line 42 String password = \"dave\";
                  Line 43-58 try { DB 查询覆盖 password }
                            catch (SQLException) { // 静默吞异常 }
                  Line 59 return password;
                  — DB 查询失败时不抛错而是返回 fallback 字面量 \"dave\",
                  完成方 if (userid_6b.equals(getPassword())) 时输入 \"dave\" 即登录成功."
```
