# Injection Family（SQL / NoSQL / Command / Code / LDAP / XPath / Template / SpEL / JNDI / JDBC URL Injection）

## 误判案例（看起来 VULNERABLE 实际有防御）

| 防御手段 | 误判场景 | 为什么安全 |
|---|---|---|
| PreparedStatement | `conn.prepareStatement("SELECT * FROM user WHERE id=?"); ps.setString(1, input);` | 参数化绑定，input 永远是数据值，无法改变 SQL 语法 |
| MyBatis `#{}` | `@Select("SELECT * FROM user WHERE id=#{id}")` | MyBatis 将 `#{}` 编译为 PreparedStatement 占位符，等同于参数化 |
| JPA Criteria API | `cb.equal(root.get("id"), input)` | 类型安全的查询构造，不拼接字符串 |
| 白名单校验 | `if (!input.matches("[a-zA-Z0-9]+")) throw ...` | 正则严格限制字符集，注入字符无法通过 |
| 整数类型强转 | `Integer.parseInt(input)` 后传入 SQL | 非数字输入抛 NumberFormatException，注入字符串无法到达 sink |
| 存储过程参数化 | `callableStatement.setString(1, input)` | 与 PreparedStatement 同理 |

## 绕过案例（看起来有防御实际可绕）

| 看似防御 | 绕过思路 | 示例 |
|---|---|---|
| PreparedStatement 拼接 | 动态表名/列名不能用占位符，开发者误用拼接 | `"SELECT * FROM " + tableName + " WHERE id=?"` — `tableName` 可控 → 注入 |
| MyBatis `${}` | `${}` 是字符串替换，不是参数化 | `@Select("SELECT * FROM ${table} WHERE id=#{id}")` — `table` 可控 |
| ORDER BY 拼接 | ORDER BY 后不支持占位符 | `"SELECT * FROM user ORDER BY " + sortBy` — `sortBy` 可控 → 注入 |
| LIKE 拼接 | PreparedStatement 内拼 `%` | `ps.setString(1, "%" + input + "%")` — input 含 `%` / `_` 通配符泄露数据（非注入但可滥用） |
| 过滤 `delete/drop/select` | 大小写混合 / 双写绕过 | `SeLeCt` / `selselectect` — 黑名单过滤不可靠 |
| 单引号转义 `\` | 反斜杠逃逸 | MySQL `GBCK` 编码下 `0xbf27` (宽字符) 吃掉转义符 |
| 正则只过滤空格 | 注释符替代空格 | `/**/UNION/**/SELECT` / `UNION%0aSELECT` |
| 内联白名单但分支遗漏 | switch-case 漏掉 default 分支 | `switch(sortBy) { case "name": ...; case "date": ...; }` 无 default → else 分支走拼接 |
| ProcessBuilder 单参数 | `sh -c` 二次解析 | `new ProcessBuilder("sh", "-c", userInput)` — `userInput` 被shell 二次展开 |
| Runtime.exec 单字符串 | 空格分割导致注入 | `Runtime.getRuntime().exec("ping " + host)` — `host="127.0.0.1; cat /etc/passwd"` |
| OGNL 沙箱 | 沙箱反射逃逸 | `#context["xwork.MethodAccessor.denyMethodExecution"]=false` 解锁方法执行 |
| SpEL 沙箱 | `T()` 类型引用绕过 | `T(java.lang.Runtime).getRuntime().exec("id")` — 直接引用任意类 |
| JNDI 限制协议 | `log4j2.formatMsgNoLookups=true` | 仅阻止 log4j 触发，其他 JNDI 调用路径不受影响 |
| LDAP 转义特殊字符 | `*` 和 `)` 组合逃逸 | `*)(uid=*))(|(uid=*` — 闭合原有过滤条件后注入新查询 |
| 模板引擎沙箱 | 沙箱内访问危险对象 | FreeMarker: `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` — 通过 `?new` 实例化任意类 |
| JDBC URL 白名单 | H2 INIT 参数注入 | `jdbc:h2:mem:test;INIT=CREATE ALIAS EXEC AS 'String shellexec(String cmd) throws ...'` — URL 格式合法但 INIT 可执行任意 SQL |
