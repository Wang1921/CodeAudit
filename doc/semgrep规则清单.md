# Semgrep 规则清单

> 自动生成于 2026-07-07 ｜ 规则总数: **146 条** / **66 个 yaml 文件** ｜ 覆盖语言: Java / Python / C / C++

> 目录结构: `semgrep_rules/custom/{java,python,cpp}/`


> `taint_required` 缺省值为 `true`（见 `src/semgrep_scanner.py:338` `metadata.get("taint_required", True)`）；`false` 走 ConfigValidator fast path。


## 1. 统计概览

### 1.1 按语言

| 语言 | 文件数 | 规则数 | 污点链类 | 配置类 | 路由提取 |
|------|--------|--------|----------|--------|----------|
| Java | 34 | 62 | 32 | 18 | 12 |
| Python | 22 | 66 | 32 | 10 | 24 |
| C/C++ | 10 | 18 | 9 | 9 | 0 |
| **合计** | **66** | **146** | **73** | **37** | **36** |

### 1.2 按漏洞类别 (vuln_class)

| vuln_class | 规则数 | 涉及语言 |
|------------|--------|---------|
| SQL Injection | 13 | C/C++/Java/Python |
| Weak Cryptography | 9 | C/C++/Java/Python |
| XXE | 8 | C/C++/Java/Python |
| Command Injection | 7 | C/C++/Java/Python |
| Path Traversal | 6 | C/C++/Java/Python |
| Unsafe Deserialization | 6 | Java/Python |
| Code Injection | 4 | Java/Python |
| NoSQL Injection | 4 | Java/Python |
| Sensitive Data in Log | 4 | C/C++/Java/Python |
| Template Injection | 4 | Java/Python |
| Unsafe Reflection | 4 | Java |
| Buffer Overflow | 3 | C/C++ |
| Hardcoded Credentials | 3 | C/C++/Java/Python |
| Insecure Temp File | 3 | Java/Python |
| SSRF | 3 | Java/Python |
| Weak Random | 3 | C/C++/Java/Python |
| XSS | 3 | Java/Python |
| Insecure Cookie | 2 | Java |
| LDAP Injection | 2 | Java/Python |
| Open Redirect | 2 | Java/Python |
| Stack Trace Exposure | 2 | Java/Python |
| XPath Injection | 2 | Java/Python |
| Zip Slip | 2 | Java/Python |
| Constant Salt | 1 | Java |
| Format String | 1 | C/C++ |
| Insecure TLS | 1 | Java |
| JDBC URL Injection | 1 | Java |
| JNDI Injection | 1 | Java |
| JWT None Algorithm | 1 | Java |
| Sensitive Data in URL | 1 | Java |
| SpEL Injection | 1 | Java |
| Static IV | 1 | Java |
| Trust Boundary Violation | 1 | Java |
| Unvalidated Forward | 1 | Java |

## 2. Java 规则明细

> 34 个 yaml / 62 条规则


### 2.1 污点链类 (taint_required: true)

| 规则 ID | 文件 | 严重度 | 漏洞类别 | CWE | 语言 | 简介 |
|---------|------|--------|----------|-----|------|------|
| `java-code-injection` | java/code-injection.yaml | ERROR | Code Injection | CWE-94 +1 | java | Code / Expression Language Injection (CWE-94 / CWE-917) Sink:<br>表达式 / 脚本引擎执行接收非字面量参数。<br>攻击者可传入 Java 类构造 / `Runtime.exec` / 反射 等 payload 实现 RCE， |
| `java-command-injection` | java/command-injection.yaml | ERROR | Command Injection | CWE-78 | java | Command Injection (CWE-78) Sink: 命令执行接口接收非字面量参数。<br>若参数来自外部输入，攻击者可注入 shell 元字符（如 `; rm -rf /` 或 `$(whoami)`）<br>实现任意命令执行 (RCE)。 |
| `java-jdbc-url-tainted` | java/jdbc-url-tainted.yaml | ERROR | JDBC URL Injection | CWE-89 +1 | java | JDBC URL Tainted (CWE-89 子类 / CWE-20) Sink:<br>`DriverManager.getConnection(url, ...)` 接收非字面量 JDBC URL。<br>攻击者可指向他们控制的数据库，触发 JDBC 驱动在"连接握手"阶段的协议级漏洞： |
| `java-jndi-injection` | java/jndi-injection.yaml | ERROR | JNDI Injection | CWE-74 +1 | java | JNDI Injection (CWE-74 / CWE-917) Sink: JNDI lookup 接收非字面量名称参数。<br>若 JNDI 名来自外部输入（HTTP header/参数/反序列化/日志内容），攻击者可传入<br>`ldap://attacker.com/Exploit` 或 `rmi://attacker.com/Exploit`，触发远端加载并 |
| `java-ldap-injection` | java/ldap-injection.yaml | ERROR | LDAP Injection | CWE-90 | java | LDAP Injection (CWE-90) Sink: LDAP 查询接口接收非字面量 filter。<br>若 filter 拼接了用户输入（如 `(&(uid=` + user + `)(pass=` + pass + `))`），<br>攻击者可注入 `*)(uid=*` 等通配符绕过鉴权或枚举账户。 |
| `java-nosql-injection` | java/nosql-injection.yaml | ERROR | NoSQL Injection | CWE-943 | java | NoSQL Injection (CWE-943) Sink: NoSQL 查询接口接收非字面量查询内容。<br>MongoDB 场景：<br>- `Document.parse(userJson)` / `BasicDBObject.parse(userJson)` / `new BasicQuery(userJson)` |
| `java-open-redirect` | java/open-redirect.yaml | ERROR | Open Redirect | CWE-601 | java | Open Redirect (CWE-601) Sink: 重定向目标接受非字面量 URL。<br>若 URL 来自外部输入，攻击者可构造 `https://attacker.com/phish` 作为 next 参数，<br>被诱导的用户访问后看到的域名还是"合法站点"，但跳转落点在攻击者控制的页面， |
| `java-path-traversal` | java/path-traversal.yaml | ERROR | Path Traversal | CWE-22 | java | Path Traversal (CWE-22) Sink: 文件 I/O 接口接收非字面量路径参数。<br>若路径含 `../` 或绝对路径跳出预期目录，攻击者可读写任意文件（如<br>`/etc/passwd`、配置文件、密钥）；写入场景更可能覆盖 webshell 达到 RCE。 |
| `java-hibernate-jpa-sql-injection` | java/sql-injection.yaml | ERROR | SQL Injection | CWE-89 | java | Hibernate / JPA SQL Injection (CWE-89) Sink: ORM 层接收非字面量 HQL/JPQL/SQL。<br>常见误区："用了 ORM 就自动防 SQLi"。实际上只要用 `createQuery(sql)` / `createNativeQuery(sql)`<br>并把用户输入拼进 `sql`，HQL 和 JPQL 解析器同样会让攻击者闭合条件 / UNION / 命令执行。 |
| `java-mybatis-provider-sql-injection` | java/sql-injection.yaml | WARNING | SQL Injection | CWE-89 | java | MyBatis @*Provider SQL Injection Risk (CWE-89): 使用了 @SelectProvider / @InsertProvider /<br>@UpdateProvider / @DeleteProvider 动态 SQL Provider。<br>Provider 类的方法负责生成 SQL 字符串，若内部拼接了用户输入（@Param 参数）， |
| `java-mybatis-sql-injection` | java/sql-injection.yaml | ERROR | SQL Injection | CWE-89 | java | MyBatis SQL Injection (CWE-89) Sink: MyBatis SQL 注解里使用了 `${...}` 字符串插值。<br>`${}` 是 MyBatis 的**字符串拼接**语法（等同于 JDBC 的 SQL 字符串 concat），<br>`#{}` 才是参数化绑定。任何接收外部输入的 `${}` 都构成 SQL 注入。 |
| `java-mybatis-sqlsession-injection` | java/sql-injection.yaml | ERROR | SQL Injection | CWE-89 | java | MyBatis SqlSession SQL Injection (CWE-89) Sink: SqlSession 的 selectXxx / insert / update / delete<br>方法直接接收非字面量 SQL 字符串。这绕过了 Mapper XML/注解的参数绑定机制（#{param}），<br>等同于 JDBC Statement.execute(sql)，任何用户输入拼入即构成 SQL 注入。 |
| `java-mybatis-xml-sql-injection` | java/mybatis-xml-sql-injection.yaml | ERROR | SQL Injection | CWE-89 | generic | MyBatis XML Mapper SQL Injection (CWE-89) Sink: XML mapper 文件中使用了 `${...}`<br>字符串插值。<br>MyBatis 的 `${param}` 是**字符串直接拼接**（等同于 JDBC 的 SQL concat）， |
| `java-sql-injection` | java/sql-injection.yaml | ERROR | SQL Injection | CWE-89 | java | SQL Injection (CWE-89) Sink: JDBC / JdbcTemplate / MyBatis 查询接口接收非字面量 SQL 语句。<br>若字符串通过拼接用户输入构造，攻击者可注入 `' OR 1=1 --` 等 SQL 片段<br>绕过鉴权、读/写/删任意数据，严重时扩展到 RCE（视数据库能力）。 |
| `java-sql-injection-chained-statement` | java/sql-injection.yaml | ERROR | SQL Injection | CWE-89 | java | SQL Injection (CWE-89) Sink: 通过 JDBC Connection 链式调用 createStatement().execute*($SQL)<br>执行非字面量 SQL。等价于把用户输入拼进 SQL 后立即执行。<br>修复建议同 `java-sql-injection`：改用 PreparedStatement 占位符 + setXxx。 |
| `java-sql-injection-spring-reactive-modern` | java/sql-injection.yaml | ERROR | SQL Injection | CWE-89 | java | SQL Injection (CWE-89) Sink: Spring reactive / 现代 fluent SQL 接口接收非字面量 SQL。<br>涉及接口：<br>- R2dbcEntityTemplate.select(Query) / .getDatabaseClient().sql(sql) |
| `java-ssrf-http-execution` | java/ssrf.yaml | ERROR | SSRF | CWE-918 | java | SSRF (CWE-918) Sink: HTTP 客户端接收非字面量 URL 发起出站请求。<br>若 URL 来自外部输入，攻击者可指向内网服务、云元数据接口<br>(http://169.254.169.254/、http://localhost:8500/、file:///etc/passwd) |
| `java-ssrf-uri-construction` | java/ssrf.yaml | WARNING | SSRF | CWE-918 | java | ⚠️ SSRF 候选 (CWE-918) Sink：仅构造 URI/URL 对象，本身不发起出站请求。<br>若该对象后续被传给 HTTP 客户端（HttpClient/RestTemplate/WebClient/openConnection 等）<br>且原始输入来自外部 HTTP 入口，则构成 SSRF。 |
| `java-spel-injection` | java/spel-injection.yaml | ERROR | SpEL Injection | CWE-94 +1 | java | SpEL Injection (CWE-917) Sink: SpelExpressionParser.parseExpression() 接收非字面量参数。<br>若参数来自外部输入，攻击者可注入任意 SpEL 表达式（如<br>T(java.lang.Runtime).getRuntime().exec(...)）实现远程代码执行 (RCE)。 |
| `java-template-injection` | java/template-injection.yaml | ERROR | Template Injection | CWE-94 +1 | java | Template Injection (CWE-94 / CWE-1336) Sink: 模板引擎接收非字面量模板内容。<br>Velocity / FreeMarker / Pebble 等引擎支持类反射与静态方法调用，<br>若模板内容来自外部输入，攻击者可构造 |
| `java-unsafe-deserialization` | java/unsafe-deserialization.yaml | ERROR | Unsafe Deserialization | CWE-502 | java | Unsafe Deserialization (CWE-502) Sink: 反序列化接口接收非字面量数据。<br>Java 原生 `readObject` 链路存在大量 gadget（CommonsCollections、ROME、<br>Spring AOP 等），攻击者构造恶意字节流可直接 RCE；YAML / XStream 同理。 |
| `java-dynamic-class-loading-quartz` | java/unsafe-dynamic-class-loading.yaml | ERROR | Unsafe Reflection | CWE-470 | java | Dynamic Class Loading (CWE-470) Sink: Quartz 定时任务通过配置字段指定 jobClassName。<br>`Class.forName(jobClassName)` 由框架内部调用，若 jobClassName 来自管理员输入，<br>攻击者可加载 org.jeecg 包下的可滥用类实现 RCE（即使有包名白名单 + 接口校验， |
| `java-dynamic-class-loading-rule-engine` | java/unsafe-dynamic-class-loading.yaml | ERROR | Unsafe Reflection | CWE-470 | java | Dynamic Class Loading (CWE-470) Sink: 规则引擎通过配置字段指定实现类名。<br>`Class.forName(ruleClass)` 由框架内部调用，若 ruleClass 来自用户输入，<br>攻击者可在白名单包空间内寻找可被滥用的实现类。 |
| `java-dynamic-class-loading-spring-bean` | java/unsafe-dynamic-class-loading.yaml | WARNING | Unsafe Reflection | CWE-470 | java | Dynamic Class Loading (CWE-470) Sink: Spring BeanDefinition 动态注册。<br>`BeanDefinitionBuilder.beanDefinition(className)` 接收非字面量类名，<br>若 className 来自外部输入，攻击者可注入任意类到 Spring 容器。 |
| `java-unsafe-reflection` | java/unsafe-reflection.yaml | ERROR | Unsafe Reflection | CWE-470 | java | Unsafe Reflection (CWE-470) Sink: 反射接口接收非字面量类名或方法名。<br>若类名来自外部输入，攻击者可加载 `java.lang.ProcessBuilder` 或 `javax.naming.InitialContext`<br>等敏感类实现 RCE；通过控制 `Method.invoke` 的参数也能攻击现有逻辑。这是 OGNL 注入 / Spring |
| `java-unvalidated-url-forward` | java/unvalidated-forward.yaml | ERROR | Unvalidated Forward | CWE-601 +1 | java | Unvalidated URL Forward (CWE-601 / CWE-552) Sink:<br>`RequestDispatcher.forward(userInput, ...)` 或 `include(userInput, ...)`<br>把用户输入当作内部路径直接转发 / 包含。 |
| `java-xpath-injection` | java/xpath-injection.yaml | ERROR | XPath Injection | CWE-643 | java | XPath Injection (CWE-643) Sink: XPath 表达式接收非字面量字符串。<br>若表达式拼接了用户输入（如 `//user[name='` + name + `']`），<br>攻击者可注入 `' or '1'='1` 绕过鉴权或枚举 XML 数据。 |
| `java-xss` | java/xss.yaml | ERROR | XSS | CWE-79 | java | Cross-Site Scripting (CWE-79) Sink: HTTP 响应输出接收非字面量内容。<br>若内容来自外部输入且未经 HTML/JS 编码，攻击者可注入<br>`<script>alert(document.cookie)</script>` 窃取会话、劫持账户、水坑攻击。 |
| `java-xxe-dom-parser` | java/xxe.yaml | ERROR | XXE | CWE-611 | java | XXE (CWE-611) Sink: DOM 解析器（DocumentBuilder / dom4j SAXReader / jdom2 SAXBuilder）<br>解析非字面量输入。这些 API 默认启用 DTD 解析和外部实体引用，<br>攻击者可注入 `<!ENTITY xxe SYSTEM "file:///etc/passwd">` 读取任意文件、 |
| `java-xxe-sax-stream` | java/xxe.yaml | ERROR | XXE | CWE-611 | java | XXE (CWE-611) Sink: SAX / StAX 流式 XML 解析器接收非字面量输入。<br>与 DOM 相比，SAX/StAX 是流式 + 事件回调，但**默认同样启用外部实体解析**，<br>攻击者仍可通过 `<!ENTITY>` 注入读文件 / SSRF / DoS。 |
| `java-xxe-transform-validate` | java/xxe.yaml | ERROR | XXE | CWE-611 | java | XXE (CWE-611) Sink: XML 转换 / 校验 / 绑定接口接收非字面量 Source。<br>涉及接口：<br>- TransformerFactory.newTransformer(Source)   ← XSLT 转换器 |
| `java-zip-slip` | java/zip-slip.yaml | ERROR | Zip Slip | CWE-22 | java | Zip Slip (CWE-22) Sink: 解压 ZipEntry / TarArchiveEntry 时直接用 `entry.getName()`<br>拼接目标路径，未做规范化校验。<br>攻击者在恶意压缩包里构造包含 `../../../etc/passwd` 的 entry name，解压后可写入 |

### 2.2 配置类 (taint_required: false)

| 规则 ID | 文件 | 严重度 | 漏洞类别 | CWE | 语言 | 简介 |
|---------|------|--------|----------|-----|------|------|
| `java-constant-salt` | java/insecure-crypto-config.yaml | ERROR | Constant Salt | CWE-760 | java | Constant Salt (CWE-760) Sink: 口令派生或哈希使用硬编码 salt。<br>salt 的作用是让相同口令产生不同哈希，阻断"彩虹表"攻击。写死的 salt 让所有用户<br>共享一个彩虹表前缀，等于没盐 —— 一旦泄露，批量爆破效率极高。 |
| `java-hardcoded-credentials` | java/hardcoded-credentials.yaml | ERROR | Hardcoded Credentials | CWE-798 +1 | java | Hardcoded Credentials (CWE-798 / CWE-259) Sink: 源码中硬编码了凭证或密钥。<br>变量名含 `password` / `secret` / `token` / `apiKey` / `accessKey` / `privateKey`<br>且直接赋值为字符串字面量，视为硬编码凭证。 |
| `java-insecure-cookie-explicit-false` | java/insecure-cookie.yaml | ERROR | Insecure Cookie | CWE-614 +1 | java | Insecure Cookie (CWE-614 / CWE-1004) Sink: Cookie 显式关闭安全属性。<br>- `setSecure(false)` 让 Cookie 在 HTTP 明文信道传输，中间人可嗅探；<br>- `setHttpOnly(false)` 让 JavaScript 可读 Cookie，XSS 能直接窃取会话。 |
| `java-insecure-cookie-missing-secure` | java/insecure-cookie.yaml | WARNING | Insecure Cookie | CWE-614 +1 | java | Insecure Cookie (CWE-614) Sink: Cookie 构造后直接 `addCookie()` 加入响应，<br>中间**没有**调用 `setSecure(true)` 或 `setHttpOnly(true)`。<br>默认情况下 `javax.servlet.http.Cookie` 的 Secure/HttpOnly 都是 false， |
| `java-insecure-trust-manager` | java/insecure-trust-manager.yaml | ERROR | Insecure TLS | CWE-295 | java | Insecure TLS TrustManager / HostnameVerifier (CWE-295) Sink:<br>空实现的 `X509TrustManager.checkServerTrusted()` 或 `HostnameVerifier.verify()` 恒返回 true。<br>这等价于"关闭 TLS 证书校验"，攻击者在同网段实施中间人（MITM）时， |
| `java-insecure-temp-file` | java/insecure-temp-file.yaml | WARNING | Insecure Temp File | CWE-377 +2 | java | Insecure Temporary File (CWE-377 / CWE-378 / CWE-379) Sink:<br>`File.createTempFile` / `Files.createTempFile` 默认创建在 `/tmp`（世界可读目录），<br>且默认权限为 `rw-r--r--`（其他本地用户可读）。 |
| `java-jwt-none-algorithm` | java/jwt-none.yaml | ERROR | JWT None Algorithm | CWE-347 | java | JWT with None / Unsigned Algorithm (CWE-347) Sink:<br>使用了 `Algorithm.none()` 或不验证签名地 parse JWT。<br>`alg: none` 意味着"无签名"，任何人都能伪造合法 JWT。加上 JWT 常被当认证令牌用， |
| `java-log-sensitive-object` | java/sensitive-data-in-log.yaml | WARNING | Sensitive Data in Log | CWE-532 | java | Sensitive Data in Log (CWE-532) — 疑似打印含敏感字段的业务对象（启发式）。<br>日志参数里出现常见"容器对象"变量名，对象所属类若含 password / token / secret /<br>community string / privKey 等字段且 `toString()` 未脱敏，会随日志泄露。 |
| `java-sensitive-data-in-log` | java/sensitive-data-in-log.yaml | WARNING | Sensitive Data in Log | CWE-532 | java | Sensitive Data in Log (CWE-532) Sink: 日志打印含密码 / token / 密钥等敏感关键字。<br>日志常被存储在中心化系统（ELK / Splunk / CloudWatch），所有运维 / 开发 / 外包人员<br>都能看到；定期备份与灾备同步又把日志复制到多处，**一次泄露永久留痕**。典型事故： |
| `java-sensitive-data-in-url` | java/sensitive-data-in-url.yaml | WARNING | Sensitive Data in URL | CWE-598 | java | Sensitive Data in URL Query (CWE-598) Sink: URL 查询串中含有<br>`password / token / secret / api_key / ssn / cvv` 等敏感字段名。<br>**不限 HTTP 方法**：GET / POST / PUT / DELETE 只要把敏感数据拼进 URL query， |
| `java-stack-trace-exposure` | java/stack-trace-exposure.yaml | WARNING | Stack Trace Exposure | CWE-209 | java | Stack Trace Exposure (CWE-209) Sink: 异常堆栈直接输出到 HTTP 响应流。<br>堆栈信息对攻击者极其有用：<br>- 暴露内部类路径 / 第三方库版本 / 数据库类型（JDBC exception） |
| `java-static-iv` | java/insecure-crypto-config.yaml | ERROR | Static IV | CWE-329 | java | Static / Zero-Filled IV (CWE-329) Sink:<br>`IvParameterSpec` 使用零填充数组或硬编码字面量作为 IV。<br>加密模式（CBC / GCM / CTR）的安全性依赖 IV 对于**每次加密**都是随机不重复的。 |
| `java-trust-boundary-violation` | java/trust-boundary.yaml | WARNING | Trust Boundary Violation | CWE-501 | java | Trust Boundary Violation (CWE-501) Sink: 把外部输入直接存入 HttpSession / Application<br>作用域，混淆了"可信服务端数据"与"不可信客户端数据"的边界。<br>一旦 session 里的属性被认为"可信"（如后续用 `session.getAttribute("role")` 做权限判断）， |
| `java-unsafe-deserialization-fastjson2-default` | java/unsafe-deserialization.yaml | WARNING | Unsafe Deserialization | CWE-502 | java | ⚠️ FastJson 2.x 反序列化警告 (CWE-502): JSON.parse/parseObject/parseArray 默认配置。<br>fastjson2 默认**不启用** autoType（与 fastjson1 不同），直接使用 JSON.parse() /<br>JSON.parseObject() / JSON.parseArray() 通常是**相对安全**的。 |
| `java-insufficient-key-size` | java/insecure-crypto-config.yaml | ERROR | Weak Cryptography | CWE-326 | java | Insufficient Asymmetric Key Size (CWE-326) Sink: RSA / DSA / DH 密钥长度 < 2048 bit。<br>- NIST SP 800-131A 已弃用 RSA/DSA ≤ 1024 位；<br>- 2048 位是当前最低安全要求，长期保密建议 3072 或 4096； |
| `java-weak-cryptography` | java/weak-cryptography.yaml | ERROR | Weak Cryptography | CWE-327 +1 | java | Weak Cryptography (CWE-327 / CWE-328) Sink: 使用了已被破解或不再推荐的密码学算法。<br>- `DES` / `DESede` / `RC2` / `RC4` / `Blowfish` 对称加密已被破解或不再安全；<br>- `AES/ECB/*` 模式不具备语义安全，相同明文块 → 相同密文块（ECB penguin）； |
| `java-weak-random` | java/weak-random.yaml | WARNING | Weak Random | CWE-330 +1 | java | Weak Random (CWE-330 / CWE-338) Sink: 使用非密码学安全的随机数生成器。<br>- `java.util.Random` 是线性同余算法，种子可由连续若干次输出反推；<br>- `Math.random()` 内部复用 `Random`，同样可预测； |
| `java-xxe-incomplete-hardening` | java/xxe.yaml | WARNING | XXE | CWE-611 | java | ⚠️ XXE (CWE-611) Sink: DOM 解析器设置了部分安全特性但缺少 disallow-doctype-decl。<br>FEATURE_SECURE_PROCESSING 限制 XSLT 处理但不阻止 DTD/外部实体解析；<br>必须同时设置 `factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` |

### 2.3 路由提取（非漏洞，severity=INFO）

| 规则 ID | 文件 | 严重度 | 漏洞类别 | CWE | 语言 | 简介 |
|---------|------|--------|----------|-----|------|------|
| `spring-api-delete-method-only` | java/spring-api.yaml | INFO | - | - | java | 发现 API (无类前缀, DELETE) -> 方法路径: $METHOD_ARGS, 方法名: $METHOD |
| `spring-api-delete-with-class-mapping` | java/spring-api.yaml | INFO | - | - | java | 发现 API (带类前缀, DELETE) -> 类基础路径: $BASE_ARGS, 方法路径: $METHOD_ARGS, 方法名: $METHOD |
| `spring-api-get-method-only` | java/spring-api.yaml | INFO | - | - | java | 发现 API (无类前缀, GET) -> 方法路径: $METHOD_ARGS, 方法名: $METHOD |
| `spring-api-get-with-class-mapping` | java/spring-api.yaml | INFO | - | - | java | 发现 API (带类前缀, GET) -> 类基础路径: $BASE_ARGS, 方法路径: $METHOD_ARGS, 方法名: $METHOD |
| `spring-api-patch-method-only` | java/spring-api.yaml | INFO | - | - | java | 发现 API (无类前缀, PATCH) -> 方法路径: $METHOD_ARGS, 方法名: $METHOD |
| `spring-api-patch-with-class-mapping` | java/spring-api.yaml | INFO | - | - | java | 发现 API (带类前缀, PATCH) -> 类基础路径: $BASE_ARGS, 方法路径: $METHOD_ARGS, 方法名: $METHOD |
| `spring-api-post-method-only` | java/spring-api.yaml | INFO | - | - | java | 发现 API (无类前缀, POST) -> 方法路径: $METHOD_ARGS, 方法名: $METHOD |
| `spring-api-post-with-class-mapping` | java/spring-api.yaml | INFO | - | - | java | 发现 API (带类前缀, POST) -> 类基础路径: $BASE_ARGS, 方法路径: $METHOD_ARGS, 方法名: $METHOD |
| `spring-api-put-method-only` | java/spring-api.yaml | INFO | - | - | java | 发现 API (无类前缀, PUT) -> 方法路径: $METHOD_ARGS, 方法名: $METHOD |
| `spring-api-put-with-class-mapping` | java/spring-api.yaml | INFO | - | - | java | 发现 API (带类前缀, PUT) -> 类基础路径: $BASE_ARGS, 方法路径: $METHOD_ARGS, 方法名: $METHOD |
| `spring-api-requestmapping-method-only` | java/spring-api.yaml | INFO | - | - | java | 发现 API (无类前缀, 方法级 RequestMapping) -> 方法路径: $METHOD_ARGS, 方法名: $METHOD |
| `spring-api-requestmapping-with-class-mapping` | java/spring-api.yaml | INFO | - | - | java | 发现 API (带类前缀, 方法级 RequestMapping) -> 类基础路径: $BASE_ARGS, 方法路径: $METHOD_ARGS, 方法名: $METHOD |

## 3. Python 规则明细

> 22 个 yaml / 66 条规则


### 3.1 污点链类 (taint_required: true)

| 规则 ID | 文件 | 严重度 | 漏洞类别 | CWE | 语言 | 简介 |
|---------|------|--------|----------|-----|------|------|
| `python-code-injection-eval-exec` | python/code-injection.yaml | ERROR | Code Injection | CWE-94 +1 | python | Code Injection (CWE-94) Sink: eval() / exec() / compile() 接收非字面量代码。<br>若参数来自用户输入，攻击者可执行任意 Python 代码 (RCE)，包括<br>`__import__('os').system('rm -rf /')` 等逃逸 payload。 |
| `python-code-injection-importlib` | python/code-injection.yaml | WARNING | Code Injection | CWE-94 | python | Code Injection (CWE-94) Sink: importlib 动态导入接收非字面量模块名。<br>importlib.import_module(user_input) 可加载任意已安装模块，配合模块副作用<br>或 __import__ 链可达成代码执行。 |
| `python-code-injection-os-exec` | python/code-injection.yaml | WARNING | Code Injection | CWE-78 | python | Code Injection (CWE-94) Sink: os.exec*() 系列接收非字面量程序路径/参数。<br>os.execl/execv/execvp/execle/execve 等直接替换进程映像，若路径/参数来自<br>用户输入可导致执行任意程序。 |
| `python-command-injection-os-system` | python/command-injection.yaml | ERROR | Command Injection | CWE-78 | python | Command Injection (CWE-78) Sink: os.system() 接收非字面量命令。<br>os.system() 通过 shell 执行命令，用户输入中的 `;` / `\|` / `$(...)` / `` ` ``<br>元字符都会触发任意命令执行 (RCE)。 |
| `python-command-injection-pexpect` | python/command-injection.yaml | ERROR | Command Injection | CWE-78 | python | Command Injection (CWE-78) Sink: pexpect / pty.spawn 接收非字面量命令。<br>这些接口内部经 shell 执行，用户输入的 shell 元字符会触发 RCE。<br>修复建议：用参数列表形式的接口，或对输入做 shlex.quote() 转义。 |
| `python-command-injection-subprocess-shell` | python/command-injection.yaml | ERROR | Command Injection | CWE-78 | python | Command Injection (CWE-78) Sink: subprocess 模块以 shell=True 执行非字面量命令。<br>shell=True 时命令经 /bin/sh -c 解释，用户输入中的 shell 元字符会触发 RCE。<br>常见 bug 模式： |
| `python-ldap-injection` | python/ldap-injection.yaml | ERROR | LDAP Injection | CWE-90 | python | LDAP Injection (CWE-90) Sink: ldap 查询过滤器接收非字面量输入。<br>python-ldap / ldap3 的 search_s / search 接收用户拼接的 filter 字符串，<br>攻击者可用 `*` 通配符或 `)(uid=*` 闭合绕过过滤。 |
| `python-nosql-injection-pymongo-eval` | python/nosql-injection.yaml | ERROR | NoSQL Injection | CWE-943 | python | NoSQL Injection (CWE-943) Sink: MongoDB db.eval() 执行非字面量 JS。<br>db.eval() 在服务端执行任意 JS，拼接用户输入即 RCE 等价物。<br>修复建议：禁止 eval 接收用户输入，用聚合管道替代。 |
| `python-nosql-injection-pymongo-where` | python/nosql-injection.yaml | ERROR | NoSQL Injection | CWE-943 | python | NoSQL Injection (CWE-943) Sink: MongoDB $where 接收非字面量 JavaScript。<br>PyMongo 的 $where 字段允许在 server 端执行 JS，拼接用户输入可 RCE 或 DoS。<br>常见 bug 模式： |
| `python-nosql-injection-redis-lua` | python/nosql-injection.yaml | ERROR | NoSQL Injection | CWE-943 | python | NoSQL Injection (CWE-943) Sink: Redis EVAL 执行非字面量 Lua 脚本。<br>redis-py 的 eval() 接收拼接的 Lua 代码可执行任意服务端逻辑。<br>修复建议：Lua 脚本字面量化，用户数据通过 KEYS/ARGV 传入。 |
| `python-open-redirect` | python/open-redirect.yaml | ERROR | Open Redirect | CWE-601 | python | Open Redirect (CWE-601) Sink: HTTP 重定向目标来自用户输入。<br>Flask redirect() / Django HttpResponseRedirect / redirect() 接收用户可控 URL，<br>可被 `//attacker.com` / `https:attacker.com` 等形态劫持跳转到钓鱼站。 |
| `python-path-traversal-open` | python/path-traversal.yaml | ERROR | Path Traversal | CWE-22 | python | Path Traversal (CWE-22) Sink: open() 接收非字面量路径。<br>若路径含 `../` 或绝对路径跳出预期目录，攻击者可读写任意文件<br>（如 /etc/passwd、配置、密钥）；写入场景更可能覆盖 webshell 达到 RCE。 |
| `python-path-traversal-os-functions` | python/path-traversal.yaml | ERROR | Path Traversal | CWE-22 | python | Path Traversal (CWE-22) Sink: os/shutil 文件操作接收非字面量路径。<br>os.remove / os.unlink / os.rename / shutil.copy / shutil.move 等若路径<br>来自用户输入，可读写删任意文件。 |
| `python-path-traversal-pathlib` | python/path-traversal.yaml | ERROR | Path Traversal | CWE-22 | python | Path Traversal (CWE-22) Sink: pathlib.Path 接收非字面量路径。<br>Path(user_input) / Path(base) / user_input 会构造可跳出 base 的路径，<br>配合 .read_text() / .write_text() / .open() 读写任意文件。 |
| `python-sql-injection-dbapi` | python/sql-injection.yaml | ERROR | SQL Injection | CWE-89 | python | SQL Injection (CWE-89) Sink: Python DB-API cursor.execute() 接收非字面量 SQL。<br>若 SQL 字符串通过 % / .format() / f-string 拼接用户输入，攻击者可注入<br>`' OR 1=1 --` 等 SQL 片段绕过鉴权、读写删任意数据。 |
| `python-sql-injection-sqlalchemy-executable` | python/sql-injection.yaml | ERROR | SQL Injection | CWE-89 | python | SQL Injection (CWE-89) Sink: SQLAlchemy Engine/Session.execute() 接收非字面量 SQL。<br>若传入 text() 包装的动态拼接 SQL，或直接传字符串，构成注入。<br>修复建议： |
| `python-sql-injection-sqlalchemy-text` | python/sql-injection.yaml | ERROR | SQL Injection | CWE-89 | python | SQL Injection (CWE-89) Sink: SQLAlchemy text() 接收非字面量 SQL。<br>text() 用于执行原生 SQL，若 SQL 字符串拼接了用户输入则构成注入。<br>注意：即使后续用 .bindparams() 绑定参数，只要 text() 的字符串本身被污染就有风险。 |
| `python-sql-injection-string-format` | python/sql-injection.yaml | ERROR | SQL Injection | CWE-89 | python | SQL Injection (CWE-89) Sink: SQL 语句通过 % / .format() / f-string 拼接构造。<br>这是 Python SQL 注入最常见的形态：把用户输入直接拼进 SQL 字符串再 execute。<br>常见 bug 模式： |
| `python-ssrf-requests` | python/ssrf.yaml | ERROR | SSRF | CWE-918 | python | SSRF (CWE-918) Sink: requests / httpx / urllib HTTP 客户端接收非字面量 URL。<br>若 URL 来自用户输入，攻击者可让服务器访问内网（如 http://127.0.0.1、<br>http://169.254.169.254 云元数据）、读本地文件（file://）、扫内网端口。 |
| `python-template-injection-django` | python/template-injection.yaml | WARNING | Template Injection | CWE-1336 | python | Template Injection / SSTI (CWE-1336) Sink: Django Template 接收非字面量模板字符串。<br>Django 模板引擎本身较安全（沙盒），但 admin/自定义视图中若用<br>Template(user_input).render(ctx) 仍可能泄露敏感数据或触发有限代码执行。 |
| `python-template-injection-jinja2` | python/template-injection.yaml | ERROR | Template Injection | CWE-1336 | python | Template Injection / SSTI (CWE-1336) Sink: Jinja2 渲染接收非字面量模板字符串。<br>render_template_string(user_input) / Template(user_input) 让用户控制模板，<br>攻击者可注入 `{{ ''.__class__.__mro__[1].__subclasses__() }}` 等 payload 达成 RCE。 |
| `python-template-injection-mako` | python/template-injection.yaml | ERROR | Template Injection | CWE-1336 | python | Template Injection / SSTI (CWE-1336) Sink: Mako 模板接收非字面量模板字符串。<br>Mako 默认可执行任意 Python 代码（<% %> 标签），用户控制模板即 RCE。<br>修复建议：模板字面量化，用户数据作为 context 传入。 |
| `python-unsafe-deserialization-jsonpickle` | python/unsafe-deserialization.yaml | ERROR | Unsafe Deserialization | CWE-502 | python | Unsafe Deserialization (CWE-502) Sink: jsonpickle.decode() 可执行任意代码。<br>jsonpickle 通过 __reduce__ 等机制支持 Python 对象反序列化，等同于 pickle 的 RCE 风险。<br>修复建议：禁止对不可信数据用 jsonpickle.decode，改用标准 json.loads。 |
| `python-unsafe-deserialization-marshal-shelve` | python/unsafe-deserialization.yaml | ERROR | Unsafe Deserialization | CWE-502 | python | Unsafe Deserialization (CWE-502) Sink: marshal / shelve 反序列化不可信数据。<br>marshal.loads() 和 shelve（基于 pickle）都可执行任意代码。<br>修复建议：禁止用于不可信数据，改用 JSON。 |
| `python-unsafe-deserialization-pickle` | python/unsafe-deserialization.yaml | ERROR | Unsafe Deserialization | CWE-502 | python | Unsafe Deserialization (CWE-502) Sink: pickle / cPickle 反序列化不可信数据。<br>pickle.loads() 在反序列化时可执行任意代码（__reduce__ 魔术方法），<br>接收用户输入的 pickle payload 等同 RCE。 |
| `python-unsafe-deserialization-yaml` | python/unsafe-deserialization.yaml | ERROR | Unsafe Deserialization | CWE-502 | python | Unsafe Deserialization (CWE-502) Sink: yaml.load() 未指定 SafeLoader。<br>PyYAML 的 yaml.load() 默认使用 FullLoader（Python 3.7+）或 unsafe loader，<br>可构造 `!!python/object/apply:os.system [...]` 等 tag 执行任意代码。 |
| `python-xpath-injection` | python/xpath-injection.yaml | ERROR | XPath Injection | CWE-643 | python | XPath Injection (CWE-643) Sink: XPath 查询接收非字面量输入。<br>lxml.etree.xpath() / ElementTree.findall() 用字符串拼接构造 XPath，<br>攻击者可闭合引号注入 `'] \| //user \| //foo['` 等表达式提取敏感节点。 |
| `python-xss-flask-render-raw` | python/xss.yaml | WARNING | XSS | CWE-79 | python | XSS (CWE-79) Sink: Flask render_template_string 模板里直接输出未转义变量。<br>Jinja2 默认 autoescape，但用 \|safe 过滤器或 {% autoescape false %} 会关闭转义。<br>修复建议：保持默认 autoescape，不要对用户输入加 \|safe。 |
| `python-xss-response-write` | python/xss.yaml | ERROR | XSS | CWE-79 | python | XSS (CWE-79) Sink: HTTP 响应直接输出非字面量内容未转义。<br>Flask/Django 中直接把用户输入写入响应体（Response/write/mark_safe）会触发反射/存储型 XSS。<br>常见 bug 模式： |
| `python-xxe-lxml` | python/xxe.yaml | ERROR | XXE | CWE-611 | python | XXE (CWE-611) Sink: lxml 默认解析外部实体。<br>lxml.etree 默认 resolve_entities=True，可被 XXE 攻击。<br>常见 bug 模式： |
| `python-xxe-xml-etree` | python/xxe.yaml | ERROR | XXE | CWE-611 | python | XXE (CWE-611) Sink: xml.etree.ElementTree 默认解析外部实体。<br>若解析来自用户的 XML，攻击者可声明外部实体读取文件<br>(`<!ENTITY xxe SYSTEM "file:///etc/passwd">`)、SSRF、或盲打 OOB。 |
| `python-zip-slip` | python/path-traversal.yaml | ERROR | Zip Slip | CWE-22 | python | Zip Slip (CWE-22) Sink: 解压归档时未校验 ZipInfo.filename，可被 `../` 写出目标目录。<br>zipfile / tarfile 解压时若直接用 entry.name 作为目标路径，恶意归档可覆盖<br>任意文件（如 ~/.ssh/authorized_keys）达成 RCE。 |

### 3.2 配置类 (taint_required: false)

| 规则 ID | 文件 | 严重度 | 漏洞类别 | CWE | 语言 | 简介 |
|---------|------|--------|----------|-----|------|------|
| `python-hardcoded-credentials` | python/hardcoded-credentials.yaml | ERROR | Hardcoded Credentials | CWE-798 +1 | python | Hardcoded Credentials (CWE-798 / CWE-259) Sink: 源码中硬编码了凭证或密钥。<br>变量名含 `password` / `secret` / `token` / `apikey` / `access_key` / `private_key`<br>且直接赋值为字符串字面量，视为硬编码凭证。 |
| `python-insecure-temp-file` | python/insecure-temp-file.yaml | ERROR | Insecure Temp File | CWE-377 | python | Insecure Temp File (CWE-377) Sink: tempfile.mktemp 产生可预测文件名。<br>tempfile.mktemp() 返回文件名但不创建文件，攻击者可在 mktemp 返回与<br>程序实际 open 之间用 symlink 抢注该路径，导致写入任意文件（symlink attack）。 |
| `python-insecure-temp-file-named-predictable` | python/insecure-temp-file.yaml | WARNING | Insecure Temp File | CWE-377 | python | Insecure Temp File (CWE-377) Sink: 用固定文件名在 /tmp 下创建文件。<br>open("/tmp/myapp_cache") 等固定路径在共享主机上可被其他用户抢注（symlink attack）。<br>该告警**无须污点链**，走 fast path 交给 BlueValidator 定性。 |
| `python-sensitive-data-in-log` | python/sensitive-data-in-log.yaml | WARNING | Sensitive Data in Log | CWE-532 | python | Sensitive Data in Log (CWE-532) Sink: 日志中输出敏感信息。<br>日志参数里直接出现敏感变量（password / secret / token / api_key / credit_card），<br>凭证会落入日志文件 / 集中化日志系统（ELK / Loki），放大泄露面。 |
| `python-stack-trace-exposure` | python/stack-trace-exposure.yaml | WARNING | Stack Trace Exposure | CWE-209 | python | Stack Trace Exposure (CWE-209) Sink: 异常堆栈直接返回给用户。<br>traceback.format_exc() / traceback.format_exception() 把内部堆栈暴露给调用方，<br>会泄露文件路径、库版本、SQL 片段，便于攻击者构造后续攻击。 |
| `python-weak-cryptography-hardcoded-key` | python/weak-cryptography.yaml | ERROR | Weak Cryptography | CWE-321 | python | Weak Cryptography (CWE-321) Sink: 硬编码密钥用于加密。<br>密钥写死在源码里，源码泄露即等价于密钥泄露。<br>该告警**无须污点链**，走 fast path 交给 BlueValidator 做静态定性。 |
| `python-weak-cryptography-hashlib` | python/weak-cryptography.yaml | ERROR | Weak Cryptography | CWE-327 +1 | python | Weak Cryptography (CWE-327 / CWE-328) Sink: hashlib 使用弱哈希算法。<br>MD5 / SHA-1 存在碰撞攻击，禁止用于签名、数据完整性、口令哈希。<br>该告警**无须污点链**（算法由代码本地决定），走 fast path 交给 BlueValidator 做静态定性。 |
| `python-weak-cryptography-pycrypto` | python/weak-cryptography.yaml | ERROR | Weak Cryptography | CWE-327 | python | Weak Cryptography (CWE-327) Sink: pycryptodome 使用弱算法。<br>DES / ARC2 / ARC4 / Blowfish 已被破解或不再安全。<br>该告警**无须污点链**，走 fast path 交给 BlueValidator 做静态定性。 |
| `python-weak-cryptography-pycrypto-ecb` | python/weak-cryptography.yaml | ERROR | Weak Cryptography | CWE-327 | python | Weak Cryptography (CWE-327) Sink: AES ECB 模式不具备语义安全。<br>相同明文块 → 相同密文块（ECB penguin），泄露明文模式。<br>修复建议：用 AES-GCM 或 AES-CBC + 随机 IV。 |
| `python-weak-random` | python/weak-random.yaml | WARNING | Weak Random | CWE-330 | python | Weak Random (CWE-330) Sink: random 模块产生非密码学安全随机数。<br>random.random() / random.randint() / random.choice() 基于 Mersenne Twister，<br>状态可预测，禁止用于 token / 密码 / 会话 ID / CSRF / 加密 IV 生成。 |

### 3.3 路由提取（非漏洞，severity=INFO）

| 规则 ID | 文件 | 严重度 | 漏洞类别 | CWE | 语言 | 简介 |
|---------|------|--------|----------|-----|------|------|
| `python-django-api-route-classbased` | python/django-api.yaml | INFO | - | - | python | 发现 API (Django class-based view) -> 路由: $RULE, 类视图: $VIEW |
| `python-django-api-route-drf-apiview` | python/django-api.yaml | INFO | - | - | python | 发现 API (Django REST @api_view) -> 方法: $METHODS, 函数: $FUNC |
| `python-django-api-route-include` | python/django-api.yaml | INFO | - | - | python | 发现 API (Django include) -> 子路由: $RULE, include: $TARGET |
| `python-django-api-route-path` | python/django-api.yaml | INFO | - | - | python | 发现 API (Django path) -> 路由: $RULE, 视图: $VIEW |
| `python-django-api-route-re-path` | python/django-api.yaml | INFO | - | - | python | 发现 API (Django re_path) -> 路由: $RULE, 视图: $VIEW |
| `python-fastapi-api-route-delete` | python/fastapi-api.yaml | INFO | - | - | python | 发现 API (FastAPI DELETE) -> 路由: $RULE, 函数名: $FUNC |
| `python-fastapi-api-route-get` | python/fastapi-api.yaml | INFO | - | - | python | 发现 API (FastAPI GET) -> 路由: $RULE, 函数名: $FUNC |
| `python-fastapi-api-route-get-async` | python/fastapi-api.yaml | INFO | - | - | python | 发现 API (FastAPI GET async) -> 路由: $RULE, 函数名: $FUNC |
| `python-fastapi-api-route-patch` | python/fastapi-api.yaml | INFO | - | - | python | 发现 API (FastAPI PATCH) -> 路由: $RULE, 函数名: $FUNC |
| `python-fastapi-api-route-post` | python/fastapi-api.yaml | INFO | - | - | python | 发现 API (FastAPI POST) -> 路由: $RULE, 函数名: $FUNC |
| `python-fastapi-api-route-post-async` | python/fastapi-api.yaml | INFO | - | - | python | 发现 API (FastAPI POST async) -> 路由: $RULE, 函数名: $FUNC |
| `python-fastapi-api-route-put` | python/fastapi-api.yaml | INFO | - | - | python | 发现 API (FastAPI PUT) -> 路由: $RULE, 函数名: $FUNC |
| `python-fastapi-api-route-router-get` | python/fastapi-api.yaml | INFO | - | - | python | 发现 API (FastAPI Router GET) -> 路由: $RULE, 函数名: $FUNC |
| `python-fastapi-api-route-router-post` | python/fastapi-api.yaml | INFO | - | - | python | 发现 API (FastAPI Router POST) -> 路由: $RULE, 函数名: $FUNC |
| `python-flask-api-route-delete` | python/flask-api.yaml | INFO | - | - | python | 发现 API (Flask DELETE) -> 路由: $RULE, 函数名: $FUNC |
| `python-flask-api-route-get` | python/flask-api.yaml | INFO | - | - | python | 发现 API (Flask GET) -> 路由: $RULE, 函数名: $FUNC |
| `python-flask-api-route-get-default` | python/flask-api.yaml | INFO | - | - | python | 发现 API (Flask GET 默认) -> 路由: $RULE, 函数名: $FUNC |
| `python-flask-api-route-patch` | python/flask-api.yaml | INFO | - | - | python | 发现 API (Flask PATCH) -> 路由: $RULE, 函数名: $FUNC |
| `python-flask-api-route-post` | python/flask-api.yaml | INFO | - | - | python | 发现 API (Flask POST) -> 路由: $RULE, 函数名: $FUNC |
| `python-flask-api-route-put` | python/flask-api.yaml | INFO | - | - | python | 发现 API (Flask PUT) -> 路由: $RULE, 函数名: $FUNC |
| `python-flask-api-route-shortcut-delete` | python/flask-api.yaml | INFO | - | - | python | 发现 API (Flask @app.delete) -> 路由: $RULE, 函数名: $FUNC |
| `python-flask-api-route-shortcut-get` | python/flask-api.yaml | INFO | - | - | python | 发现 API (Flask @app.get) -> 路由: $RULE, 函数名: $FUNC |
| `python-flask-api-route-shortcut-post` | python/flask-api.yaml | INFO | - | - | python | 发现 API (Flask @app.post) -> 路由: $RULE, 函数名: $FUNC |
| `python-flask-api-route-shortcut-put` | python/flask-api.yaml | INFO | - | - | python | 发现 API (Flask @app.put) -> 路由: $RULE, 函数名: $FUNC |

## 4. C/C++ 规则明细

> 10 个 yaml / 18 条规则


### 4.1 污点链类 (taint_required: true)

| 规则 ID | 文件 | 严重度 | 漏洞类别 | CWE | 语言 | 简介 |
|---------|------|--------|----------|-----|------|------|
| `cpp-command-injection-createprocess` | cpp/command-injection.yaml | WARNING | Command Injection | CWE-78 | cpp | Command Injection (CWE-78) Sink: CreateProcess 接收非字面量命令行。<br>Windows CreateProcess 的 lpCommandLine 若拼接用户输入且 bInheritHandles +<br>lpApplicationName=NULL，会经 shell 解析，存在命令注入风险。 |
| `cpp-command-injection-exec` | cpp/command-injection.yaml | WARNING | Command Injection | CWE-78 | c, cpp | Command Injection (CWE-78) Sink: exec* / spawn* 接收非字面量程序路径。<br>execl/execlp/execv/execvp 等直接替换进程映像，若路径/参数来自用户输入<br>可导致执行任意程序。Windows 的 _wsystem / CreateProcess 同理。 |
| `cpp-command-injection-system` | cpp/command-injection.yaml | ERROR | Command Injection | CWE-78 | c, cpp | Command Injection (CWE-78) Sink: system() / popen() 接收非字面量命令。<br>system() 通过 shell 执行命令，用户输入中的 `;` / `\|` / `$(...)` / `` ` ``<br>元字符都会触发任意命令执行 (RCE)。 |
| `cpp-format-string-printf` | cpp/format-string.yaml | ERROR | Format String | CWE-134 | c, cpp | Format String (CWE-134) Sink: printf 系列接收非字面量格式字符串。<br>若格式字符串来自用户输入，攻击者可注入 %s / %x / %n 读取栈内存<br>或写入任意地址（%n 写入已格式化的字符数），达成信息泄露或 RCE。 |
| `cpp-path-traversal-cpp17-filesystem` | cpp/path-traversal.yaml | WARNING | Path Traversal | CWE-22 | cpp | Path Traversal (CWE-22) Sink: std::filesystem::path 接收非字面量路径。<br>C++17 filesystem::path 构造后配合 read/write 可读写任意文件。<br>修复建议：用 std::filesystem::weakly_canonical 解析后比较是否在 base 目录内。 |
| `cpp-path-traversal-fopen` | cpp/path-traversal.yaml | ERROR | Path Traversal | CWE-22 | c, cpp | Path Traversal (CWE-22) Sink: 文件 I/O 接口接收非字面量路径。<br>fopen / ifstream / ofstream / fstream 接收用户输入路径，<br>若含 `../` 或绝对路径可读写任意文件。 |
| `cpp-sql-injection-string-concat` | cpp/sql-injection.yaml | ERROR | SQL Injection | CWE-89 | c, cpp | SQL Injection (CWE-89) Sink: SQL 语句通过字符串拼接构造。<br>C/C++ 中没有 ORM，SQL 拼接是常见模式，用户输入拼入即构成注入。<br>常见 bug 模式： |
| `cpp-xxe-libxml2` | cpp/xxe.yaml | ERROR | XXE | CWE-611 | c, cpp | XXE (CWE-611) Sink: libxml2 解析 XML 未禁用外部实体。<br>libxml2 的 xmlReadFile / xmlReadMemory 默认解析外部实体，<br>攻击者可通过 `<!ENTITY xxe SYSTEM "file:///etc/passwd">` 读取任意文件、SSRF。 |
| `cpp-xxe-pugixml-tinyxml` | cpp/xxe.yaml | WARNING | XXE | CWE-611 | cpp | XXE (CWE-611) Sink: pugixml / tinyxml 解析 XML 默认行为可能解析外部实体。<br>pugixml 默认不解析 DTD/外部实体（相对安全），但若显式开启 parse_full /<br>parse_dtd 标志仍可被利用。tinyxml2 默认安全但需确认 ProcessEntities 设置。 |

### 4.2 配置类 (taint_required: false)

| 规则 ID | 文件 | 严重度 | 漏洞类别 | CWE | 语言 | 简介 |
|---------|------|--------|----------|-----|------|------|
| `cpp-buffer-overflow-sprintf` | cpp/buffer-overflow.yaml | ERROR | Buffer Overflow | CWE-120 +1 | c, cpp | Buffer Overflow (CWE-120 / CWE-134) Sink: sprintf / vsprintf 无边界检查。<br>sprintf 把格式化结果写入固定大小缓冲区，输出超长即溢出。<br>vsprintf 同理。两者都不接受 size 参数。 |
| `cpp-buffer-overflow-strcpy` | cpp/buffer-overflow.yaml | ERROR | Buffer Overflow | CWE-120 +1 | c, cpp | Buffer Overflow (CWE-120 / CWE-121) Sink: strcpy / strcat / gets 无边界检查。<br>strcpy / strcat 不检查目标缓冲区大小，源字符串过长即栈/堆溢出，<br>可覆盖返回地址达成 RCE。gets 同理（已被 C11 标准删除）。 |
| `cpp-buffer-overflow-unsafe-runtime` | cpp/buffer-overflow.yaml | ERROR | Buffer Overflow | CWE-120 | c, cpp | Buffer Overflow (CWE-120) Sink: scanf 系列无字段宽度限制。<br>scanf / sscanf / fscanf 的 %s 不带宽度即等价 gets，可溢出缓冲区。<br>常见 bug 模式： |
| `cpp-hardcoded-credentials` | cpp/hardcoded-credentials.yaml | ERROR | Hardcoded Credentials | CWE-798 +1 | cpp | Hardcoded Credentials (CWE-798 / CWE-259) Sink: 源码中硬编码凭证/密钥。<br>C/C++ 中常以字符串字面量形式硬编码密码、token、API key。<br>二进制反编译极易提取，源码泄露即等价于凭证泄露。 |
| `cpp-sensitive-data-in-log` | cpp/sensitive-data-in-log.yaml | WARNING | Sensitive Data in Log | CWE-532 | c, cpp | Sensitive Data in Log (CWE-532) Sink: 日志中输出敏感信息。<br>printf / syslog / std::cout 输出含 password / secret / token 的字符串，<br>凭证会落入日志文件 / syslog 集中系统，放大泄露面。 |
| `cpp-weak-cryptography-ecb` | cpp/weak-cryptography.yaml | ERROR | Weak Cryptography | CWE-327 | c, cpp | Weak Cryptography (CWE-327) Sink: AES ECB 模式不具备语义安全。<br>相同明文块 → 相同密文块（ECB penguin），泄露明文模式。<br>修复建议：用 AES-GCM 或 AES-CBC + 随机 IV。 |
| `cpp-weak-cryptography-hardcoded-key` | cpp/weak-cryptography.yaml | ERROR | Weak Cryptography | CWE-321 | cpp | Weak Cryptography (CWE-321) Sink: 硬编码密钥用于加密。<br>密钥写死在源码里，源码泄露即等价于密钥泄露（C/C++ 二进制反编译也易提取）。<br>该告警**无须污点链**，走 fast path 交给 BlueValidator 做静态定性。 |
| `cpp-weak-cryptography-openssl` | cpp/weak-cryptography.yaml | ERROR | Weak Cryptography | CWE-327 +1 | c, cpp | Weak Cryptography (CWE-327 / CWE-328) Sink: OpenSSL 使用弱算法。<br>MD5 / SHA-1 / DES / RC4 已被破解或不再安全。<br>该告警**无须污点链**（算法由代码本地决定），走 fast path 交给 BlueValidator 做静态定性。 |
| `cpp-weak-random` | cpp/weak-random.yaml | WARNING | Weak Random | CWE-330 | c, cpp | Weak Random (CWE-330) Sink: rand() / random() 产生非密码学安全随机数。<br>C 标准库的 rand() / random() 基于线性同余或类似 PRNG，状态可预测，<br>禁止用于 token / 密码 / 会话 ID / CSRF / 加密 IV 生成。 |
