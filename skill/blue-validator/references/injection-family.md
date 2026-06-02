# Injection Family（SQL / NoSQL / Command / Code / LDAP / XPath / Template / SpEL / JNDI / JDBC URL Injection）

## 共性

所有 Injection 类漏洞的本质都是：**结构化语句的"语法层"和"数据层"被混淆**。
攻击者输入控制了 sink 的"指令字符串"而不仅是"数据值"，因此能改变指令含义。

## 防御机制速查（搜这些即可见）

### SQL 类
- **`PreparedStatement.setXxx(idx, value)`** —— 参数化绑定（**前提：SQL 是字面量 + ? 占位**）
- `JdbcTemplate.queryForXxx(sql, Object[] args)` —— 第二参数是参数数组才安全
- MyBatis `#{param}`（参数绑定）而非 `${param}`（字符串拼接）
- 类型强转：`Integer.parseInt(input)` 后注入到 SQL（数字型可接受）
- ESAPI / OWASP `Encoder.encodeForSQL(codec, input)`

### Command 类
- 调用前严格白名单 / 正则校验 `if (!Pattern.matches("[a-zA-Z0-9_-]+", input)) throw ...`
- 避免 shell 元字符（直接传字符串数组 `new String[]{cmd, arg1, arg2}` 而非单字符串）
- 类型转换为枚举：`OperationType.valueOf(input.toUpperCase())`

### Code/SpEL/JNDI 类
- 完全禁用动态求值或限定到极严格白名单
- SpEL: `SimpleEvaluationContext.forReadOnlyDataBinding()` 而非默认 `StandardEvaluationContext`
- JNDI: `System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase", "false")` + JDK ≥ 8u191

## 常见误判（容易把 VULNERABLE 错判为 DEFENDED）

- ❌ 看到 `PreparedStatement` 类名就判 DEFENDED —— 关键看 SQL 字符串是字面量 + 用 `?` 占位
- ❌ 看到一个 if 校验就判 DEFENDED —— sink 里的其他参数可能仍可控
- ❌ "教学项目 / WebGoat" 借口 —— 一律按生产代码标准
- ❌ "用户必须登录" 借口 —— 已登录用户仍可触发注入
- ❌ "前端会校验" 借口 —— 前端校验不作数

## 证据引用范例

**DEFENDED 时**：
```
defense_analysis: "Line 42 PreparedStatement statement = conn.prepareStatement(
                   "SELECT * FROM users WHERE id = ?");
                  Line 43 statement.setInt(1, userId);
                  — SQL 是字面量 + ? 占位 + setInt 类型化绑定 userId,
                  不存在字符串拼接,符合 OWASP 推荐参数化模式。"
```

**VULNERABLE 时**：
```
suspicion_reason: "Line 44 prepareStatement(\"SELECT password FROM challenge_users
                   WHERE userid='\" + username + \"' and password='\" + password + \"'\")
                   — username 和 password 都来自 @RequestParam (line 32),
                   通过字符串拼接进入 SQL 语句,未使用 ? 占位 + setString 绑定."
```
