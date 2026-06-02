# Credentials & Backdoor Family（Hardcoded Credentials / Hardcoded Backdoor）

## 区别

| | Hardcoded Credentials | Hardcoded Backdoor |
|---|---|---|
| 形态 | **变量赋值**层面 | **业务判定**层面 |
| 例子 | `String password = "admin123"` | `if (input.equals("admin123")) return success()` |
| 风险 | 被泄露后任意人可用 | 知道字面量即可绕过认证 |

## sink 模式速查

### Hardcoded Credentials
- `String password / secret / apiKey / token / privateKey = "literal"` —— 字段/局部变量赋值
- `@Value("plaintext-password")` 注入
- `Properties.setProperty("db.password", "literal")`
- `Connection conn = DriverManager.getConnection(url, "user", "literal-password")` —— 内联凭证
- `Cipher.init(..., new SecretKeySpec("literal-key".getBytes(), "AES"))`
- 配置文件 `application.properties` / `.yml` 含明文密码（按文件路径过滤）

### Hardcoded Backdoor
- `if ($X.equals("literal")) return success(...)`
- `if ("literal".equals($X)) return $OK.build()`
- `if ($X.equals(getStaticPassword())) ...` 其中 `getStaticPassword()` 返回字面量
- 多用户身份验证里某个字面量是 master 凭证

## 数据流追溯重点

### Hardcoded Credentials
fast-path：直接看变量赋值是否字面量字符串即可。

### Hardcoded Backdoor
1. 找 `if-equals-literal` 模式；
2. 看 if 分支内：是否 `return success(...)` / `return $OK.build()` / `setAuthenticated(true)` / `setAdmin(true)` 等"放行/提权"动作；
3. 反向：if 分支只是返回错误码 / 失败结果（如 `return failed(...)`）则**不是**后门，可能只是错误处理。

## 常见误判

- ❌ "密码看起来像占位符 'CHANGE_ME'" —— 仍是 Hardcoded Credentials，提示开发者修但代码本身就是漏洞
- ❌ "if 里只是 quiz 答案校验" —— 看上下文，是否真的用于鉴权 / 提权决策；quiz 答题端点的 `equals("Solution 4")` 非后门
- ❌ "代码注释说仅 dev 环境" —— 注释不可信，看是否有 `@Profile("dev")` / 环境检查代码
- ❌ "字面量是从常量类引入的" —— `if (input.equals(Constants.ADMIN_KEY))` 仍是后门，Constants.ADMIN_KEY 也是硬编码
