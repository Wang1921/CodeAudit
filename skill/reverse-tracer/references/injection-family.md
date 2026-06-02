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

## 常见误判（容易把 VULNERABLE 错判为 DEFENDED）

- ❌ 看到 `PreparedStatement` 类名就判 DEFENDED —— 关键看 SQL 字符串是字面量 + 用 `?` 占位
- ❌ 看到一个 if 校验就判 DEFENDED —— sink 里的其他参数可能仍可控
- ❌ "教学项目 / WebGoat" 借口 —— 一律按生产代码标准
- ❌ "用户必须登录" 借口 —— 已登录用户仍可触发注入
- ❌ "前端会校验" 借口 —— 前端校验不作数
