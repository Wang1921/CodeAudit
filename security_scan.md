# Security Scan Report — AI 识别出的静态/动态漏洞列表

> 扫描目标：WebGoat (Java/Spring 教学靶场)
> 扫描引擎：CodeAudit 多智能体审计系统 (v13 baseline)
> 报告生成时间：2026-05-16 09:31:35
> 数据来源：reports/SUMMARY.md + reports/vulnerability_*.json (共 133 条)

---

## 全局摘要

| 维度 | 数值 |
|---|---:|
| **漏洞总数** | 133 |
| Critical | 31 |
| High | 63 |
| Medium | 38 |
| Low | 1 |
| 涉及文件数 | 72 |
| 涉及 API 路由数 (unique) | 64 |


## 按扫描类别分布

| 扫描类别 | 漏洞数 | 占比 |
|---|---:|---:|
| A. 静态定性漏洞 (Static / Fast-Path) | 37 | 27.8% |
| B. 动态污点链漏洞 (Dynamic / Taint-Driven) | 53 | 39.8% |
| C. 业务逻辑漏洞 (Business Logic / LLM Reasoning) | 43 | 32.3% |


## 按漏洞类型分布 (按数量降序)

| vuln_type | CWE | 数量 | 扫描类别 |
|---|---|---:|---|
| **Hardcoded Backdoor** | CWE-798 | 16 | C 业务逻辑 |
| **SQL Injection** | CWE-89 | 16 | B 动态 |
| **Weak Random** | CWE-330 | 14 | A 静态 |
| **Hardcoded Credentials** | CWE-798 | 11 | A 静态 |
| **SSRF** | CWE-918 | 10 | B 动态 |
| **Path Traversal** | CWE-22 | 9 | B 动态 |
| **IDOR** | CWE-639 | 7 | C 业务逻辑 |
| **Authentication Bypass** | CWE-287 | 6 | C 业务逻辑 |
| **Race Condition** | CWE-362 | 6 | C 业务逻辑 |
| **Open Redirect** | CWE-601 | 6 | B 动态 |
| **Sensitive Data in Log** | CWE-532 | 6 | A 静态 |
| **Insufficient Anti-Automation** | CWE-307 | 4 | C 业务逻辑 |
| **Mass Assignment** | CWE-915 | 4 | B 动态 |
| **Insecure Cookie** | CWE-614 | 3 | A 静态 |
| **Unsafe Deserialization** | CWE-502 | 2 | B 动态 |
| **XXE** | CWE-611 | 2 | B 动态 |
| **Weak Cryptography** | CWE-327 | 2 | A 静态 |
| **Command Injection** | CWE-78 | 1 | B 动态 |
| **NoSQL Injection** | CWE-943 | 1 | B 动态 |
| **XSS** | CWE-79 | 1 | B 动态 |
| **Insecure Temp File** | CWE-377 | 1 | A 静态 |
| **Zip Slip** | CWE-22 | 1 | B 动态 |

---

## A. 静态定性漏洞 (Static / Fast-Path)  (共 37 条)

> `metadata.taint_required: false`,Semgrep 命中即漏洞,无须污点链追踪。BlueValidator 直接做配置/算法/敏感数据等本地证据裁决。

### Weak Random (CWE-330, 14 条)

| # | 严重度 | 文件:行 | 入口路由 | 简短描述 |
|---:|---|---|---|---|
| 1 | Medium | `ImageServlet.java:21` | `-` | [发现] 使用了不安全的随机数生成器  [防御分析] 代码在第 21 行使用了 `new Random().nextInt(10000)` 生成 PIN 码，Random 类是线性同余生成器，不具备密码学安全性。该 PIN 码被嵌入到返回的 |
| 2 | Medium | `PasswordResetLink.java:15` | `-` | [发现] 使用了不安全的伪随机数生成器 Random，可能导致密码重置链接可预测  [防御分析] 代码在第15行使用了 Random 类生成伪随机数，该类的随机数生成器是弱的，容易被预测。特别是在处理 admin 用户时，还使用了固定的种子 |
| 3 | Medium | `EncodingAssignment.java:37` | `-` | [发现] 使用了不够安全的随机数生成器  [防御分析] 第37行使用`new Random()`生成随机数，该随机数生成器是线性同余生成器，不具备密码学安全性，可预测性高，用于选择密码可能导致安全问题 |
| 4 | Medium | `HashingAssignment.java:37` | `-` | [发现] 使用了不够安全的随机值  [防御分析] 代码中使用 `new Random()` 生成随机索引来选择秘密字符串，`Random` 类是不安全的伪随机数生成器，其随机性不足以满足密码学场景的安全要求，可能导致秘密值可被预测 |
| 5 | Medium | `HashingAssignment.java:55` | `-` | [发现] 使用了不安全的随机数生成器  [防御分析] 代码中使用 new Random().nextInt() 来随机选择 SECRETS 数组中的元素，Random 类在 Java 中是不安全的伪随机数生成器，其输出结果可以被预测，不适合 |
| 6 | Medium | `CSRFGetFlag.java:39` | `-` | [发现] 使用了不安全的Random类生成随机数  [防御分析] 代码在第39、45、56行使用了java.util.Random类生成随机数，该类生成的随机数是伪随机数，安全性较低，可被预测。这些随机数被用来设置用户会话中的flag值，可 |
| 7 | Medium | `CSRFGetFlag.java:45` | `-` | [发现] 使用了不安全的 Random 类生成随机值  [防御分析] CSRFGetFlag.java 中的 Random 对象用于生成 flag 值，该值参与安全相关的操作（作为 CSRF 攻击成功的标志）。使用 java.util.Ra |
| 8 | Medium | `CSRFGetFlag.java:56` | `-` | [发现] 使用了不安全的随机数生成器  [防御分析] 代码中使用 `new Random()` 生成随机数用于设置 `csrf-get-success` 值，该值会作为 flag 返回到响应中。`Random` 类是伪随机数生成器，其种子可 |
| 9 | Medium | `HijackSessionAuthenticationProvider.java:25` | `-` | [防御分析] 第25行使用了new Random().nextLong() & Long.MAX_VALUE生成静态变量id，Random类是Java中提供的伪随机数生成器，其种子是基于系统时间的，并且生成的序列是可预测的。该id变量在第3 |
| 10 | Medium | `HijackSessionAuthenticationProvider.java:56` | `-` | [发现] 使用了不安全的伪随机数生成器  [防御分析] 代码中使用 ThreadLocalRandom.current().nextDouble() 作为安全相关决策的随机源，ThreadLocalRandom 虽然线程安全，但不是加密安全 |
| 11 | Medium | `JWTRefreshEndpoint.java:76` | `-` | [发现] 使用了不够随机的方法生成刷新令牌  [防御分析] 第76行使用RandomStringUtils.randomAlphabetic(20)生成刷新令牌，该方法使用的随机数生成器不够安全，可能导致令牌可预测 |
| 12 | Medium | `JWTSecretKeyEndpoint.java:38` | `-` | [发现] 使用了不安全的随机数生成器Random.nextInt()来选择JWT密钥，可能导致密钥可被预测  [防御分析] 代码第38行使用Random.nextInt()来随机选择SECRETS数组中的元素作为JWT密钥的基础，Rando |
| 13 | Medium | `EncDec.java:16` | `-` | [发现] 使用了不够随机的随机值或加密学上弱的伪随机数生成器  [防御分析] 代码中使用 `RandomStringUtils.randomAlphabetic(10)` 生成作为加密盐值的 SALT，该方法使用的是不安全的伪随机数生成器， |
| 14 | Medium | `BlindSendFileAssignment.java:54` | `-` | [发现] 使用了不安全的随机数生成方法 randomAlphabetic(10)  [防御分析] 该代码使用 org.apache.commons.lang3.RandomStringUtils.randomAlphabetic(10) 生 |

### Hardcoded Credentials (CWE-798, 11 条)

| # | 严重度 | 文件:行 | 入口路由 | 简短描述 |
|---:|---|---|---|---|
| 1 | Critical | `SolutionConstants.java:10` | `-` | [发现] 使用了硬编码的凭证  [防御分析] 代码中直接定义了硬编码的密码常量PASSWORD，值为"!!webgoat_admin_1234!!"，该常量位于公共接口SolutionConstants中，可能被多个类访问使用，存在安全风险 |
| 2 | Critical | `Assignment7.java:36` | `-` | [发现] 代码中存在硬编码的管理员密码重置链接，可能导致安全风险。  [防御分析] 该代码中存在硬编码的管理员密码重置链接（ADMIN_PASSWORD_LINK），并且在 resetPassword 方法中直接使用该硬编码值进行比较，没有 |
| 3 | Critical | `JWTRefreshEndpoint.java:45` | `-` | [防御分析] 代码中第45行和第46行分别硬编码了密码 `PASSWORD = "bm5nhSkxCXZkKRy4"` 和 JWT 签名密钥 `JWT_PASSWORD = "bm5n3SkxCX4kKRy4"`，这些硬编码的敏感信息可以被 |
| 4 | Critical | `JWTRefreshEndpoint.java:46` | `-` | [发现] 使用硬编码的JWT密钥  [防御分析] 第46行定义了私有静态常量JWT_PASSWORD，其值为"bm5n3SkxCX4kKRy4"，该密钥被用于JWT令牌的签名和验证过程（第73行和第91行、第121行）。硬编码的密钥存在严重 |
| 5 | Critical | `SampleAttack.java:27` | `-` | [发现] 使用了硬编码凭据  [防御分析] 第27行定义了私有的静态最终变量secretValue，其值硬编码为"secr37Value"，并在第46行的业务逻辑中用于验证用户输入的param1是否与该硬编码值匹配，构成硬编码凭据漏洞。 |
| 6 | Critical | `MissingFunctionAC.java:14` | `-` | [发现] 使用硬编码凭证  [防御分析] 该代码中存在硬编码的密码盐值 PASSWORD_SALT_SIMPLE（值为 DeliberatelyInsecure1234）和 PASSWORD_SALT_ADMIN（值为 Deliberate |
| 7 | Critical | `MissingFunctionAC.java:15` | `-` | [发现] 使用硬编码凭证  [防御分析] 代码中明确定义了公共静态常量 PASSWORD_SALT_ADMIN 并赋值为 DeliberatelyInsecure1235，这是典型的硬编码凭证漏洞。无任何代码级证据表明该硬编码值被覆盖、场景 |
| 8 | Critical | `ResetLinkAssignment.java:44` | `-` | [发现] 使用了硬编码的密码  [防御分析] 代码中第44-45行定义了静态常量 PASSWORD_TOM_9 作为 Tom 用户的默认密码，该密码被硬编码在代码中，违反了安全最佳实践。虽然这是一个教学项目，但根据强约束要求，仍需视为真漏洞 |
| 9 | Critical | `ActuatorExposureTask.java:28` | `-` | [发现] static final String LEAKED_API_KEY = "INTERNAL-API-KEY-987";  [防御分析] 第28行定义了硬编码的API密钥LEAKED_API_KEY，该密钥在第37行的actuat |
| 10 | Critical | `DefaultCredentialsTask.java:29` | `-` | [发现] 代码中使用了硬编码的默认密码"admin"  [防御分析] 该代码在第29行定义了硬编码的默认密码"admin"，并在第45行的登录验证逻辑中使用。这符合CWE-798（使用硬编码凭证）和CWE-259（使用硬编码密码）的漏洞定义 |
| 11 | Critical | `VerboseErrorTask.java:29` | `-` | [发现] 使用硬编码凭证  [防御分析] 第29行定义了静态常量LEAKED_TOKEN = "STAGING-TOKEN-42"，该硬编码凭证在第44行通过/trigger接口泄露到响应中，在第51行和第67行被用于访问控制和任务验证，构 |

### Sensitive Data in Log (CWE-532, 6 条)

| # | 严重度 | 文件:行 | 入口路由 | 简短描述 |
|---:|---|---|---|---|
| 1 | Medium | `PasswordResetLink.java:41` | `-` | [防御分析] 代码第41行使用System.out.println直接打印包含username变量的信息，username为用户输入的敏感信息，无任何脱敏处理，符合CWE-532的特征 |
| 2 | Medium | `PasswordResetLink.java:42` | `-` | [发现] Password reset link containing sensitive data is printed to console log  [防御分析] 密码重置链接是敏感信息，代码在第42-44行将其直接输出到控制台日志中 |
| 3 | Medium | `LogBleedingTask.java:31` | `-` | [防御分析] 在 LogBleedingTask 类的构造函数中，使用 log.info 方法将敏感数据（admin 的密码，经过 Base64 编码）写入日志文件。该密码是通过 UUID.randomUUID() 生成的真实密码，用于后续 |
| 4 | Medium | `SqlInjectionLesson6b.java:55` | `-` | [发现] 在日志中记录敏感信息  [防御分析] 代码中使用 sqle.printStackTrace() 将 SQLException 堆栈信息打印到控制台，可能包含敏感的数据库连接信息或 SQL 查询执行细节，构成敏感数据泄露风险 |
| 5 | Medium | `SqlInjectionLesson6b.java:59` | `-` | [防御分析] 在 SqlInjectionLesson6b.java 文件中，第 59 行使用 e.printStackTrace() 将异常信息打印到控制台/日志中。异常对象 e 可能包含敏感信息，如数据库连接错误、SQL 执行错误等，这 |
| 6 | Medium | `SSRFTask1.java:47` | `-` | [发现] Insertion of Sensitive Information into Log File  [防御分析] 在 SSRFTask1.java 的第 47 行，catch 块中调用了 e.printStackTrace()，这 |

### Insecure Cookie (CWE-614, 3 条)

| # | 严重度 | 文件:行 | 入口路由 | 简短描述 |
|---:|---|---|---|---|
| 1 | Medium | `JWTVotesEndpoint.java:114` | `-` | [防御分析] 代码中创建了名为 access_token 的 Cookie 来存储 JWT 令牌，但未设置 Secure 属性和 HttpOnly 属性。Secure 属性缺失会导致 Cookie 在 HTTP 连接中也会发送，增加了令牌被 |
| 2 | Medium | `JWTVotesEndpoint.java:119` | `-` | [防御分析] 在登录接口的两个分支中（第114行和第119行），创建的Cookie对象均未设置HttpOnly和Secure属性。HttpOnly属性未设置会导致Cookie可被客户端脚本访问，存在XSS攻击风险；Secure属性未设置会导 |
| 3 | Medium | `SpoofCookieAssignment.java:58` | `-` | [发现] 无  [防御分析] 代码在第 58-60 行创建了一个用于清理的 Cookie，但没有设置 Secure 和 HttpOnly 属性，不符合安全标准。 |

### Weak Cryptography (CWE-327, 2 条)

| # | 严重度 | 文件:行 | 入口路由 | 简短描述 |
|---:|---|---|---|---|
| 1 | High | `HashingAssignment.java:39` | `-` | [发现] 使用了MD5这种已被破解的哈希算法，存在安全风险  [防御分析] 代码在第39行明确使用了MessageDigest.getInstance("MD5")来计算哈希值，MD5算法已经被证明存在严重的安全缺陷，容易受到碰撞攻击，不适 |
| 2 | High | `HashingAssignment.java:84` | `-` | [发现] 使用了可能存在风险的加密算法  [防御分析] 第84行的`getHash`方法接受用户输入的`algorithm`参数，并直接用于创建MessageDigest实例，可能导致使用弱加密算法的风险。同时，第39行明确使用了MD5弱哈 |

### Insecure Temp File (CWE-377, 1 条)

| # | 严重度 | 文件:行 | 入口路由 | 简短描述 |
|---:|---|---|---|---|
| 1 | Low | `ProfileZipSlip.java:67` | `-` | [防御分析] 使用用户输入的用户名作为临时目录前缀，可能导致安全问题，因为用户名可能包含恶意字符或路径。 |

---

## B. 动态污点链漏洞 (Dynamic / Taint-Driven)  (共 53 条)

> `metadata.taint_required: true`,需 ReverseTracer 追溯到 HTTP 用户输入,再经 RedValidator 构造 PoC + BlueValidator 复核全局/局部防御。

### SQL Injection (CWE-89, 16 条)

| # | 严重度 | 文件:行 | 入口路由 | 简短描述 |
|---:|---|---|---|---|
| 1 | High | `UserService.java:53` | `/register.mvc` | [发现] 用户在注册页面输入的用户名（username）未经过任何SQL注入防护处理，直接拼接到CREATE SCHEMA SQL语句中执行，导致SQL注入漏洞。虽然UserForm对用户名有正则表达式验证（只允许小写字母、数字和连字符）， |
| 2 | Critical | `Assignment5.java:44` | `/challenge/5` | [发现] 该调用链存在SQL注入漏洞，因为在login方法中直接将用户输入的username_login和password_login参数拼接成SQL查询语句，没有进行任何SQL注入防护处理，导致攻击者可以通过输入恶意的SQL语句来绕过认证 |
| 3 | High | `JWTHeaderKIDEndpoint.java:73` | `/JWT/kid/delete` | [发现] JWT token 由用户通过 /JWT/kid/delete 接口的 token 参数传入，攻击者可恶意构造包含恶意 kid 字段的 JWT token，该字段在 SQL 查询中未经过任何验证和转义，直接拼接在 SQL 语句中， |
| 4 | High | `SqlInjectionChallenge.java:57` | `/SqlInjectionAdvanced/register` | [发现] 用户输入的 username 参数未经过任何 SQL 注入防护处理，直接拼接到 SQL 查询字符串中，导致 SQL 注入漏洞。攻击者可以通过输入包含 SQL 特殊字符（如 '、--、OR 等）的用户名来执行恶意 SQL 命令，如查 |
| 5 | High | `SqlInjectionLesson6a.java:72` | `/SqlInjectionAdvanced/attack6a` | [发现] 该调用链存在 SQL 注入漏洞，因为用户输入的 userId 参数直接拼接到 SQL 查询字符串中，未进行任何安全处理（如使用 PreparedStatement 参数化查询）。攻击者可通过输入包含 SQL 特殊字符的字符串（如  |
| 6 | High | `SqlInjectionLesson10.java:56` | `/SqlInjection/attack10` | [发现] 用户输入的 action_string 参数直接拼接在 SQL 查询中，没有进行任何防 SQL 注入处理，导致可以执行恶意 SQL 语句  [攻击面] 用户输入的action参数直接拼接在SQL查询的LIKE子句中，攻击者可以通过 |
| 7 | High | `SqlInjectionLesson2.java:49` | `/SqlInjection/attack2` | [发现] 用户输入的 query 参数直接传递到 SQL 语句执行，未进行任何过滤或预编译处理，导致 SQL 注入漏洞  [攻击面] 用户输入的 query 参数直接作为完整的 SQL 语句传递到 Statement.executeQuer |
| 8 | High | `SqlInjectionLesson3.java:47` | `/SqlInjection/attack3` | [发现] 用户输入的query参数直接传递到statement.executeUpdate方法执行，没有进行任何SQL注入防护措施，导致可以执行任意SQL语句  [攻击面] 攻击者通过HTTP POST请求向/SqlInjection/at |
| 9 | High | `SqlInjectionLesson4.java:46` | `/SqlInjection/attack4` | [发现] 该调用链存在SQL注入漏洞，因为用户传入的query参数未经过任何安全处理，直接拼接成SQL语句并执行，导致攻击者可以输入恶意SQL代码执行任意数据库操作。  [攻击面] 用户输入的query参数直接传递到statement.ex |
| 10 | High | `SqlInjectionLesson5.java:65` | `/SqlInjection/attack5` | [发现] 用户传入的query参数直接拼接到SQL语句中执行，没有进行任何SQL注入防护处理，导致SQL注入漏洞  [攻击面] 用户直接传入完整的SQL查询语句，无任何过滤或参数化处理，可直接执行恶意SQL命令  [防御分析] 代码中没有任 |
| 11 | High | `SqlInjectionLesson5a.java:52` | `/SqlInjection/assignment5a` | [发现] 该调用链存在SQL注入漏洞，因为用户传入的account、operator、injection参数在completed方法中直接拼接成accountName，然后在injectableQuery方法中与SQL查询字符串拼接，形成动 |
| 12 | High | `SqlInjectionLesson5b.java:48` | `/SqlInjection/assignment5b` | [发现] 在 SqlInjectionLesson5b.injectableQuery() 方法中，构造 SQL 查询语句时使用了字符串拼接方式处理 accountName 参数，导致 SQL 注入漏洞。虽然 login_count 参数使 |
| 13 | High | `SqlInjectionLesson8.java:142` | `/SqlInjection/attack8` | [发现] 用户输入的name和auth_tan参数在injectableQueryConfidentiality方法中拼接成SQL查询语句query，然后query作为参数传递给log方法，在log方法中进一步拼接成logQuery，最终通 |
| 14 | High | `SqlInjectionLesson8.java:62` | `/SqlInjection/attack8` | [发现] 用户输入的name和auth_tan参数未经任何 sanitization 处理，直接拼接到SQL查询字符串中，导致SQL注入漏洞。  [攻击面] 通过注入' OR '1'='1到name或auth_tan参数，构造永真条件从而获 |
| 15 | Critical | `SqlInjectionLesson9.java:65` | `/SqlInjection/attack9` | [发现] 用户输入的 name 和 auth_tan 参数未经过任何安全处理，直接拼接到 SQL 查询字符串中，导致 SQL 注入漏洞  [攻击面] 利用 SQL 注入漏洞，通过注入恶意 SQL 代码修改查询逻辑，实现对员工薪资的非法篡改  |
| 16 | High | `SqlInjectionLesson9.java:94` | `/SqlInjection/attack9` | [发现] 该调用链存在SQL注入漏洞，因为在injectableQueryIntegrity方法中直接将用户输入的name和auth_tan参数拼接到SQL查询字符串中，然后在getSqlInt方法中执行该查询，未对输入进行任何安全处理。  |

<details>
<summary>展开样例 (SqlInjectionLesson9.java): PoC + 修复建议</summary>

**攻击向量**: 用户名参数username传入后直接拼接在SQL语句中，未经过有效转义处理，可通过注入SQL注入payload攻击。尽管有正则表达式验证只允许[a-z0-9-]字符，但仍需检查是否存在其他参数或绕过方式，不过此处username参数本身可通过符合正则的输入触发潜在的SQL注入（如使用双引号闭合）。

**PoC payload**:
```
{"username":"test\"; DROP SCHEMA public; --","password":"password1","matchingPassword":"password1","agree":"true"}
```

**最大影响**: 可通过注入SQL语句执行任意数据库操作，包括创建/删除数据库、表，查询/修改数据等，严重威胁数据库安全。

</details>

### SSRF (CWE-918, 10 条)

| # | 严重度 | 文件:行 | 入口路由 | 简短描述 |
|---:|---|---|---|---|
| 1 | High | `Assignment7.java:81` | `/challenge/7` | [发现] 该调用链存在SSRF漏洞，因为在sendPasswordResetLink方法中直接使用HttpServletRequest的getRequestURL()构造URI对象，可能导致攻击者通过恶意构造请求URL实现服务器端请求伪造。 |
| 2 | High | `JWTHeaderJKUEndpoint.java:57` | `/JWT/jku/delete` | [发现] 用户可控制传入的JWT token，通过在JWT头部设置恶意的jku声明，指向内部或外部恶意URL，导致服务器发起请求，存在SSRF漏洞  [攻击面] 攻击者可以构造包含恶意jku声明的JWT token，将jku值设置为内网地址 |
| 3 | High | `OpenRedirectTask1.java:40` | `/OpenRedirect/task1` | [发现] 用户输入的url参数直接被用于构造URI对象，没有对URL的合法性进行严格验证，可能导致SSRF攻击  [攻击面] 用户输入的url参数直接被用于构造URI对象，虽然对协议进行了http/https的校验，但未对URI的其他部分进 |
| 4 | High | `OpenRedirectTask2.java:44` | `/OpenRedirect/task2` | [发现] 用户输入的url参数直接用于构造URI对象，虽然有简单的过滤检查，但仍然存在SSRF漏洞风险  [攻击面] 构造包含"webgoat" substring但实际指向外部恶意域名的URL，例如使用URL路径或参数中包含"webgoa |
| 5 | High | `OpenRedirectTask3.java:48` | `/OpenRedirect/task3` | [发现] 该调用链中，用户输入的target参数经URL解码后直接用于构造URI对象，存在服务器端请求伪造（SSRF）漏洞。虽然有简单的内部主机判断逻辑，但可通过构造特殊URL（如使用@符号的用户信息字段）绕过该判断。  [攻击面] 通过构 |
| 6 | High | `OpenRedirectTask4.java:56` | `/OpenRedirect/task4` | [发现] 用户输入的 target 参数在经过 URL 解码后直接传递给 URI 构造函数，存在服务器端请求伪造 (SSRF) 风险  [攻击面] 利用 URL 双编码技术，构造包含外部主机的恶意 target 参数，使第一次解码后看起来是 |
| 7 | High | `OpenRedirectTask4.java:67` | `/OpenRedirect/task4` | [发现] 用户传入的target参数经过两次URL解码后，被用于构建URI对象(secondUri)，该过程可能导致SSRF漏洞。因为攻击者可以传入经过双重编码的恶意URL，绕过第一次解码后的验证逻辑，从而实现服务器端请求伪造。  [攻击面 |
| 8 | High | `ResetLinkAssignmentForgotPassword.java:80` | `/PasswordReset/ForgotPassword/create-pas` | [发现] 在 sendPasswordResetLink 方法中，host 参数来自于 HTTP 请求头中的 Host 字段，该字段可被攻击者随意篡改。随后 host 参数被传递到 sendMailToUser 方法，并被用于构造 Pass |
| 9 | High | `ProfileUploadRetrieval.java:111` | `/PathTraversal/random-picture` | [发现] getProfilePicture方法接受用户输入的id参数，直接拼接成文件路径创建File对象，然后在响应的Location头部使用catPicture.getName()构造新的URI。虽然方法中有简单的参数校验（检查quer |
| 10 | High | `ProfileUploadRetrieval.java:115` | `/PathTraversal/random-picture` | [发现] 在 getProfilePicture 方法中，catPicture.getName() 是通过用户传入的 id 参数构造的，当 id 参数包含恶意内容时，可能会导致 SSRF 漏洞。虽然有简单的字符验证（检查 .. 和 /），但 |

<details>
<summary>展开样例 (ProfileUploadRetrieval.java): PoC + 修复建议</summary>

**攻击向量**: 攻击者可以通过构造恶意的请求URL，使得uri.getScheme()和uri.getHost()被篡改，进而在发送的密码重置邮件中生成恶意链接。当受害者点击该链接时，可能会被引导到攻击者控制的服务器，造成信息泄露或其他攻击。

**PoC payload**:
```
发送POST请求到/challenge/7，参数email为test@example.com，同时在请求的Host头中注入恶意域名，例如：Host: attacker.com。
```

**最大影响**: 攻击者可以利用该漏洞进行服务器端请求伪造，可能导致内部网络资源访问、敏感信息泄露等攻击。

</details>

### Path Traversal (CWE-22, 9 条)

| # | 严重度 | 文件:行 | 入口路由 | 简短描述 |
|---:|---|---|---|---|
| 1 | High | `ProfileUploadBase.java:112` | `/PathTraversal/profile-picture` | [发现] 在 getProfilePictureAsBase64 方法中，当处理用户的 profile 图片时，直接使用了 profileDirectoryFiles[0] 作为 FileInputStream 的参数，但实际过滤逻辑使用了 |
| 2 | Critical | `ProfileUploadBase.java:51` | `/PathTraversal/profile-upload` | [发现] 用户可以通过 /PathTraversal/profile-upload 接口的 fullName 参数传入恶意路径（如 ../../../../../etc/passwd），导致文件被写入到预期目录之外的位置，造成路径遍历漏洞  |
| 3 | Critical | `ProfileUploadBase.java:70` | `/PathTraversal/profile-upload` | [发现] 在 `ProfileUpload.uploadFileHandler` 方法中，`username` 参数直接从 HTTP 请求中获取（通过 `@CurrentUsername` 注解），然后传递给 `ProfileUploadB |
| 4 | High | `ProfileUploadRetrieval.java:101` | `/PathTraversal/random-picture` | [发现] 用户可通过请求参数 id 传入路径遍历字符，如 "../../path-traversal-secret"，从而访问到 catPicturesDirectory 目录外的文件，尽管代码在第 94 行对查询字符串进行了初步检查，但仍 |
| 5 | High | `ProfileUploadRetrieval.java:54` | `/PathTraversal/random-picture` | [发现] 在ProfileUploadRetrieval类中，第101行使用用户提供的id参数构建文件路径时，虽然在第94行检查了queryParams中是否包含..或/，但这种检查方式不够严格，仍可能被绕过。例如，使用URL编码的../或 |
| 6 | High | `ProfileZipSlip.java:79` | `/PathTraversal/zip-slip` | [发现] 该代码存在路径遍历漏洞，因为它直接使用ZipEntry的名称（e.getName()）作为文件路径的一部分来创建新文件，而没有对这些名称进行适当的验证或规范化处理。攻击者可以通过上传包含恶意路径的ZIP文件（如../../mali |
| 7 | High | `ProfileZipSlip.java:81` | `/PathTraversal/zip-slip` | [发现] 在 processZipUpload 方法中，直接使用 ZipEntry 的名称 e.getName() 构造 File 对象，未对文件名进行任何验证或清理，可能导致路径遍历攻击（如 e.getName() 为 "../../.. |
| 8 | High | `Ping.java:32` | `/ (GET请求，通过@GetMapping注解在Ping类上)` | [发现] 该代码存在路径遍历漏洞，因为username参数是外部可控的，直接用于构造文件路径。攻击者可以通过传入包含路径遍历字符（如../）的username参数，访问应用程序所在目录之外的文件。  [攻击面] 通过传入包含路径遍历字符（如 |
| 9 | High | `FileServer.java:79` | `/fileupload` | [发现] 在 FileServer.java 的 importFile 方法中，处理文件上传时直接使用了 multipartFile.getOriginalFilename() 作为文件名，没有对文件名进行任何路径 traversal 检查 |

<details>
<summary>展开样例 (FileServer.java): PoC + 修复建议</summary>

**攻击向量**: 1. 利用 execute 方法中 fullName 参数的路径遍历漏洞，上传文件到任意目录 2. 利用 getProfilePicture 方法读取该文件

**PoC payload**:
```
POST /PathTraversal/profile-upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW
...
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="uploadedFile"; filename="test.jpg"
Content-Type: image/jpeg
...
test content
...
------WebKi
```

**最大影响**: 任意文件读取

</details>

### Open Redirect (CWE-601, 6 条)

| # | 严重度 | 文件:行 | 入口路由 | 简短描述 |
|---:|---|---|---|---|
| 1 | Medium | `OpenRedirectRealRedirect.java:19` | `/OpenRedirect/realRedirect` | [发现] 第 19 行接受用户传入的 url 参数，未做任何验证就直接返回 redirect: + url 的 ModelAndView，导致开放重定向漏洞  [攻击面] 直接传入恶意重定向 URL 参数，利用开放重定向漏洞将用户导向恶意网 |
| 2 | Medium | `OpenRedirectRealRedirect.java:21` | `/OpenRedirect/realRedirect` | [发现] 该调用链存在漏洞是因为用户可以通过请求参数 `url` 传入任意 URL，服务端直接将其拼接到 "redirect:" 后返回，导致 URL 重定向到不受信任的站点，符合 CWE-601 开放重定向漏洞的特征。  [攻击面] 用户 |
| 3 | Medium | `OpenRedirectTask1.java:48` | `/OpenRedirect/task1` | [发现] 该接口信任用户传入的URL参数直接进行重定向，虽然对内部主机进行了简单过滤，但未对重定向地址进行严格的白名单校验，属于典型的开放重定向漏洞。  [攻击面] 攻击者可以构造恶意URL参数，绕过内部主机过滤，实现任意外部网站重定向。例 |
| 4 | Medium | `OpenRedirectTask2.java:33` | `/OpenRedirect/task2` | [发现] 第37行仅检查url是否包含'webgoat'子串，攻击者可构造包含'webgoat'但实际跳转到外部恶意域名的URL实现绕过，例如http://attacker.com?foo=webgoat  [攻击面] 构造包含'webgo |
| 5 | Medium | `OpenRedirectTask3.java:44` | `/OpenRedirect/task3` | [发现] 第44行判断 URL 是否为内部地址的逻辑存在缺陷，使用 startsWith() 方法仅检查了 URL 的前缀，攻击者可以通过构造类似 http://webgoat.local@evil.com 的 URL 来绕过检查，实际访问 |
| 6 | Medium | `OpenRedirectTask4.java:41` | `/OpenRedirect/task4` | [发现] 第 49 行和第 64 行的双重解码逻辑存在缺陷。攻击者可以通过输入类似 `https://webgoat.local%2540evil.com` 的 payload，第一次解码后仍以 `https://webgoat.local |

<details>
<summary>展开样例 (OpenRedirectTask4.java): PoC + 修复建议</summary>

**攻击向量**: 直接传入恶意重定向 URL 参数，利用开放重定向漏洞将用户导向恶意网站

**PoC payload**:
```
url=https://attacker.com
```

**最大影响**: 钓鱼攻击、用户信息泄露

</details>

### Mass Assignment (CWE-915, 4 条)

| # | 严重度 | 文件:行 | 入口路由 | 简短描述 |
|---:|---|---|---|---|
| 1 | High | `BypassRestrictionsFieldRestrictions.java:20` | `/BypassRestrictions/FieldRestrictions` | [发现] 方法completed()通过@RequestParam注解直接接收所有前端提交的字段，但前端可能会通过修改请求参数名、添加隐藏字段或修改字段值类型来绕过限制，导致Mass Assignment漏洞。  [攻击面] 前端通过修改表 |
| 2 | High | `StoredXssComments.java:96` | `-` | [防御分析] 使用ObjectMapper.readValue()方法将JSON字符串直接反序列化为Comment对象，允许攻击者通过发送额外的属性来修改对象的任何字段，存在大量赋值漏洞。 |
| 3 | High | `ContentTypeAssignment.java:77` | `-` | [发现] 使用 ObjectMapper.readValue() 进行反序列化时未限制可绑定的属性，存在 mass assignment 漏洞  [防御分析] 代码使用 ObjectMapper.readValue() 直接将 JSON 字 |
| 4 | High | `MailboxController.java:42` | `/mail` | [发现] sendEmail 方法（第 42 行）使用 @RequestBody 直接绑定 Email 对象并保存到数据库，但 Email 类中包含 recipient 字段，攻击者可通过构造请求篡改邮件接收者。同时，该接口缺少鉴权和权限控 |

<details>
<summary>展开样例 (MailboxController.java): PoC + 修复建议</summary>

**攻击向量**: 前端通过修改表单参数值绕过服务端的字段校验，例如：修改select参数值为option3，radio参数值为option3，checkbox参数值为other，shortInput参数值为长度大于5的字符串，readOnlyInput参数值为非change的字符串

**PoC payload**:
```
select=option3&radio=option3&checkbox=other&shortInput=123456&readOnlyInput=modified
```

**最大影响**: 成功绕过服务端的字段校验，完成攻击任务

</details>

### Unsafe Deserialization (CWE-502, 2 条)

| # | 严重度 | 文件:行 | 入口路由 | 简短描述 |
|---:|---|---|---|---|
| 1 | Critical | `SerializationHelper.java:23` | `/InsecureDeserialization/task` | [发现] 该调用链存在漏洞，因为它直接接收外部用户可控的 token 参数，经过 Base64 解码后进行不安全的反序列化操作，可能导致远程代码执行等严重安全问题  [攻击面] 利用 ysoserial 等工具生成针对 Commons Co |
| 2 | Critical | `VulnerableComponentsLesson.java:42` | `/VulnerableComponents/attack1` | [发现] 该调用链存在不安全反序列化漏洞，因为用户可通过 /VulnerableComponents/attack1 接口传入任意 XML 数据作为 payload 参数，服务器使用 XStream 库直接对该参数进行反序列化操作，且未对输 |

<details>
<summary>展开样例 (VulnerableComponentsLesson.java): PoC + 修复建议</summary>

**攻击向量**: 利用 ysoserial 等工具生成针对 Commons Collections 等常用库的恶意序列化 payload，通过 Base64 编码后作为 token 参数传入，触发不安全的反序列化操作，实现远程代码执行

**PoC payload**:
```
使用 ysoserial 生成 payload：java -jar ysoserial.jar CommonsCollections4 'calc.exe' | base64 -w 0，将生成的 Base64 字符串作为 token 参数发送 POST 请求到 /InsecureDeserialization/task
```

**最大影响**: RCE (远程代码执行)

</details>

### XXE (CWE-611, 2 条)

| # | 严重度 | 文件:行 | 入口路由 | 简短描述 |
|---:|---|---|---|---|
| 1 | High | `CommentsCache.java:79` | `/xxe/simple` | [发现] 在 SimpleXXE.createNewComment 方法中，用户传入的 XML 数据（commentStr）被直接传递给 CommentsCache.parseXml 方法，并且 securityEnabled 参数被设置为 |
| 2 | High | `CommentsCache.java:82` | `/xxe/simple` | [发现] 在 SimpleXXE.createNewComment 方法中，用户传入的 XML 数据（commentStr）被直接传递给 CommentsCache.parseXml 方法，并且 securityEnabled 参数被设置为 |

<details>
<summary>展开样例 (CommentsCache.java): PoC + 修复建议</summary>

**攻击向量**: 通过发送包含外部实体引用的 XML 数据到 /xxe/simple 接口，由于 XML 解析器未禁用外部实体引用，攻击者可以读取服务器本地文件或发起 SSRF 攻击。

**PoC payload**:
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE comment [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<comment>
<text>&xxe;</text>
<author>attacker</author>
<date>2024-05-15</date>
</comment>
```

**最大影响**: 敏感数据泄漏（如读取 /etc/passwd 文件内容）

</details>

### Command Injection (CWE-78, 1 条)

| # | 严重度 | 文件:行 | 入口路由 | 简短描述 |
|---:|---|---|---|---|
| 1 | Critical | `VulnerableTaskHolder.java:67` | `/InsecureDeserialization/task` | [发现] 该调用链存在命令注入漏洞，因为用户可以通过 POST 请求发送经过精心构造的序列化后的 VulnerableTaskHolder 对象，其中 taskAction 字段可以包含恶意命令。当服务器对该对象进行反序列化时，会在 rea |

<details>
<summary>展开样例 (VulnerableTaskHolder.java): PoC + 修复建议</summary>

**攻击向量**: 通过 POST 请求发送经过 Base64 编码的恶意序列化 VulnerableTaskHolder 对象，其中 taskAction 字段构造满足条件的命令（如 ping 或 sleep），利用反序列化过程中执行命令的漏洞

**PoC payload**:
```
构造一个 taskAction 为 "ping 127.0.0.1"（满足 startsWith("ping") 且长度 <22）的 VulnerableTaskHolder 对象，序列化为字节数组，Base64 编码（替换 + 为 -, / 为 _）后作为 token 参数发送 POST 请求到 /InsecureDeserialization/task
```

**最大影响**: RCE（远程命令执行），攻击者可执行服务器上的命令

</details>

### NoSQL Injection (CWE-943, 1 条)

| # | 严重度 | 文件:行 | 入口路由 | 简短描述 |
|---:|---|---|---|---|
| 1 | High | `SqlInjectionLesson9.java:65` | `/SqlInjection/attack9` | [发现] 用户提供的name和auth_tan参数在第50-55行直接拼接成SQL查询字符串，未进行任何安全过滤或参数化处理，导致在第65行执行时存在SQL注入漏洞  [攻击面] 通过在name或auth_tan参数中注入SQL语句，闭合原 |

<details>
<summary>展开样例 (SqlInjectionLesson9.java): PoC + 修复建议</summary>

**攻击向量**: 通过在name或auth_tan参数中注入SQL语句，闭合原查询的引号并添加恶意SQL命令，以实现SQL注入攻击。例如，在auth_tan参数中注入'; UPDATE employees SET salary = salary * 10 WHERE auth_tan = '3SL99A' -- 来修改John的工资

**PoC payload**:
```
name=Smith&auth_tan='; UPDATE employees SET salary = salary * 10 WHERE auth_tan = '3SL99A' --
```

**最大影响**: 数据篡改（如修改工资）、数据泄露、数据库结构损坏

</details>

### XSS (CWE-79, 1 条)

| # | 严重度 | 文件:行 | 入口路由 | 简短描述 |
|---:|---|---|---|---|
| 1 | High | `Ping.java:35` | `/ (GET)` | [发现] logLine变量由User-Agent和text参数直接拼接而成，然后写入日志文件，存在XSS风险  [攻击面] 通过构造恶意的User-Agent或text参数，注入XSS payload到日志文件中。当该日志文件被Web应用 |

<details>
<summary>展开样例 (Ping.java): PoC + 修复建议</summary>

**攻击向量**: 通过构造恶意的User-Agent或text参数，注入XSS payload到日志文件中。当该日志文件被Web应用读取并显示在页面上时，XSS payload会被执行。

**PoC payload**:
```
GET请求中设置User-Agent为<script>alert('XSS')</script>，或设置text参数为<script>alert('XSS')</script>
```

**最大影响**: 应用层的XSS攻击，可能导致用户会话劫持、敏感信息泄露或恶意脚本执行

</details>

### Zip Slip (CWE-22, 1 条)

| # | 严重度 | 文件:行 | 入口路由 | 简短描述 |
|---:|---|---|---|---|
| 1 | Critical | `ProfileZipSlip.java:79` | `/PathTraversal/zip-slip` | [发现] 该调用链存在Zip Slip漏洞，因为在处理上传的ZIP文件时，没有对ZIP条目名称进行严格的路径验证。攻击者可以通过构造包含../等路径遍历字符的ZIP条目，将文件解压到临时目录之外的任意位置，从而导致文件覆盖或任意文件写入攻击 |

<details>
<summary>展开样例 (ProfileZipSlip.java): PoC + 修复建议</summary>

**攻击向量**: 攻击者可以构造一个包含路径遍历字符（如../）的ZIP文件条目，例如条目名称为"../../../../etc/passwd"。当WebGoat处理这个ZIP文件时，会将该条目解压到tmpZipDirectory之外的位置，导致任意文件写入或覆盖攻击。

**PoC payload**:
```
构造一个ZIP文件，其中包含一个名为"../../../../etc/passwd"的条目，然后通过/PathTraversal/zip-slip接口上传该ZIP文件。
```

**最大影响**: 攻击者可以利用该漏洞写入或覆盖服务器上的任意文件，导致敏感数据泄漏、服务器配置篡改或远程代码执行（RCE）等严重后果。

</details>

---

## C. 业务逻辑漏洞 (Business Logic / LLM Reasoning)  (共 43 条)

> LogicAuditor 从 API 路由出发,跨文件追读业务代码,推理 IDOR / 鉴权 / 并发 / 状态机等漏洞。9 类业务白名单。

### Hardcoded Backdoor (CWE-798, 16 条)

| # | 严重度 | 文件:行 | 入口路由 | 简短描述 |
|---:|---|---|---|---|
| 1 | Critical | `Assignment1.java:31` | `/challenge/1` | [发现] 第 31 行 `ipAddressKnown` 变量被硬编码为 `true`，任何情况下都会满足 IP 地址已知的条件，导致该验证逻辑完全失效  [攻击面] 攻击者可以通过发送包含admin用户名和正确密码的请求直接通过验证，因为 |
| 2 | Critical | `Assignment7.java:62` | `/challenge/7/reset-password/{link}` | [发现] 在 Assignment7.java 的 resetPassword 方法中，第 62 行使用了硬编码的 ADMIN_PASSWORD_LINK（值为 375afe1104f4a487a73823c50a9292a2）作为密码重置 |
| 3 | Critical | `ClientSideFilteringFreeAssignment.java:25` | `/clientSideFiltering/getItForFree` | [发现] 第 25 行定义了硬编码的 SUPER_COUPON_CODE = "get_it_for_free"，第 30 行直接通过 equals 比较 checkoutCode 与该硬编码值，存在白名单后门漏洞  [攻击面] 直接使用硬 |
| 4 | Critical | `ClientSideFilteringFreeAssignment.java:30` | `/clientSideFiltering/getItForFree` | [发现] 该代码存在硬编码后门漏洞，使用固定的优惠券代码"get_it_for_free"作为访问控制条件，通过HTTP POST请求的checkoutCode参数接收用户输入，与硬编码的SUPER_COUPON_CODE进行比较，可能被恶 |
| 5 | High | `CryptoUtil.java:48` | `/crypto/signing/getprivate` | [发现] 该API接口直接暴露了获取RSA私钥的功能，通过HTTP请求可直接获取私钥的PEM格式字符串，存在严重的安全隐患。  [攻击面] 通过HTTP GET请求访问API接口 /crypto/signing/getprivate，无需任 |
| 6 | Critical | `ForgedReviews.java:38` | `/csrf/review` | [发现] 第 38 行定义了硬编码的弱 CSRF 验证令牌 `weakAntiCSRF = "2aa14227b9a13d0bede0388a7fba9aa9"`，第 92 行直接使用该硬编码值进行 CSRF 验证，攻击者可通过获取该硬编码 |
| 7 | Critical | `InsecureLoginTask.java:21` | `/InsecureLogin/task` | [发现] 第 21 行使用硬编码的用户名"CaptainJack"和密码"BlackPearl"进行身份验证，存在硬编码后门漏洞  [攻击面] 该接口接受用户传入的 username 和 password 参数，只要传入硬编码的用户名"Ca |
| 8 | Critical | `JWTDecodeEndpoint.java:23` | `/JWT/decode` | [发现] 该代码在 JWTDecodeEndpoint.decode() 方法中实现了一个硬编码的后门逻辑。当用户输入为 "user" 时，直接返回成功结果，否则返回失败结果。这种硬编码的凭证检查方式存在严重安全隐患，因为攻击者可以通过简单 |
| 9 | High | `JWTHeaderKIDEndpoint.java:92` | `/JWT/kid/delete` | [发现] 该端点存在硬编码后门，当JWT token中的username字段值为'Jerry'时，会直接返回失败结果并显示特定反馈信息，可能被用于限制特定用户的操作权限。  [攻击面] 攻击者可以通过构造一个包含'username'字段为' |
| 10 | Critical | `SampleAttack.java:46` | `/lesson-template/sample-attack` | [发现] 第 27 行定义了硬编码的 secretValue = "secr37Value"，第 46 行通过与用户传入的 param1 直接比较作为成功条件，属于硬编码后门逻辑  [攻击面] 通过 HTTP POST 请求访问 /less |
| 11 | Critical | `SampleAttack.java:46` | `/lesson-template/sample-attack` | [发现] 该代码包含一个硬编码后门，通过检查请求参数param1是否等于硬编码的secretValue（"secr37Value"）来判断是否成功。攻击者可以通过向/lesson-template/sample-attack发送包含正确pa |
| 12 | Critical | `ResetLinkAssignment.java:71` | `/PasswordReset/reset/login` | [发现] 该代码在第71行使用了硬编码的密码 PASSWORD_TOM_9（值为 "somethingVeryRandomWhichNoOneWillEverTypeInAsPasswordForTom"）作为Tom用户登录的验证逻辑，存在 |
| 13 | High | `ActuatorExposureTask.java:57` | `/SecurityMisconfiguration/task3` | [发现] 该方法通过 @PostMapping 注解暴露了一个 HTTP 入口路由 /SecurityMisconfiguration/task3，接受 apiKey 参数。然后使用硬编码的 LEAKED_API_KEY 进行比对，存在硬编 |
| 14 | Critical | `VerboseErrorTask.java:67` | `/SecurityMisconfiguration/task2` | [发现] 代码中存在硬编码的后门令牌 STAGING-TOKEN-42，当用户提交该令牌时会成功通过验证，存在安全隐患  [攻击面] 通过传入硬编码的后门令牌 STAGING-TOKEN-42 到 /SecurityMisconfigura |
| 15 | Critical | `SqlInjectionLesson6b.java:41` | `/SqlInjectionAdvanced/attack6b` | [发现] getPassword()方法中硬编码了默认密码"dave"作为fallback值，当数据库查询失败时会返回该硬编码密码，存在硬编码凭证漏洞  [攻击面] 攻击者可以通过向/SqlInjectionAdvanced/attack6 |
| 16 | High | `SqlInjectionLesson2.java:54` | `/SqlInjection/attack2` | [发现] 该代码接收用户控制的query参数，执行SQL查询后，检查结果集中的department字段是否等于"Marketing"，如果是则返回成功反馈。这种硬编码的判断逻辑可能被利用，因为用户可以通过SQL注入篡改查询结果，使depar |

<details>
<summary>展开样例 (SqlInjectionLesson2.java): PoC + 修复建议</summary>

**攻击向量**: 攻击者可以通过发送包含admin用户名和正确密码的请求直接通过验证，因为ipAddressKnown变量硬编码为true，使得IP地址验证逻辑完全失效。

**PoC payload**:
```
POST /challenge/1 HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded

username=admin&password=正确的密码
```

**最大影响**: 未授权访问，攻击者可以直接通过该接口获取挑战1的flag，绕过了IP地址验证逻辑。

</details>

### IDOR (CWE-639, 7 条)

| # | 严重度 | 文件:行 | 入口路由 | 简短描述 |
|---:|---|---|---|---|
| 1 | High | `Assignment7.java:60` | `/challenge/7` | [发现] 1. Assignment7.java第60行resetPassword方法直接根据路径参数link判断是否为ADMIN_PASSWORD_LINK(硬编码值:375afe1104f4a487a73823c50a9292a2)，无 |
| 2 | High | `IDORLogin.java:52-62` | `/IDOR/login` | [发现] 第52行检查 username 存在后，第53行仅对 "tom" 用户进行密码校验，其他用户（如 "bill"）的密码校验逻辑缺失，导致任意密码即可登录非 "tom" 用户  [攻击面] 对于非"tom"用户（如"bill"），只 |
| 3 | High | `IDORViewOwnProfileAltUrl.java:45` | `/IDOR/profile/alt-path` | [发现] 第41-44行仅验证url路径结构而未对用户身份与资源id的归属关系进行充分校验，用户可通过构造包含其他用户id的url来访问其用户资料  [攻击面] 该代码在处理用户输入的URL时，仅检查了URL的路径结构，但未对用户身份与请求 |
| 4 | High | `JWTVotesEndpoint.java:104` | `/JWT/votings/login` | [发现] 第 55 行 JWT_PASSWORD 使用固定值 "victory" 硬编码密钥，且通过 TextCodec.BASE64.encode("victory") 暴露在源代码中，攻击者可轻松获取并伪造任意 JWT 令牌，包括将 a |
| 5 | High | `ResetLinkAssignment.java:113` | `/PasswordReset/reset/change-password` | [发现] checkIfLinkIsFromTom() 函数内判断逻辑有误，resetLink 验证未与用户强绑定。该函数通过 userToTomResetLink.get(username) 拿预期值再与 form.getResetLin |
| 6 | High | `ResetLinkAssignment.java:80` | `/PasswordReset/reset/reset-password/{lin` | [发现] 第80行resetPassword()方法中，通过路径参数link直接查找重置链接，第83行仅检查resetLinks.contains(link)而不校验链接归属（如link是否属于当前用户）；跨文件追读PasswordChan |
| 7 | High | `ResetLinkAssignmentForgotPassword.java:54` | `/PasswordReset/ForgotPassword/create-pas` | [发现] 第 54-56 行对 host 头的校验仅检查是否包含 webwolf 的 host 和 port，但 Host 头可被攻击者任意伪造，导致攻击者可利用自己的邮箱触发向 Tom 发送重置链接的逻辑，进而可能劫持 Tom 的账号密码 |

<details>
<summary>展开样例 (ResetLinkAssignmentForgotPassword.java): PoC + 修复建议</summary>

**攻击向量**: 直接访问硬编码的admin密码重置链接即可获取flag，无需任何鉴权或用户身份校验

**PoC payload**:
```
GET /challenge/7/reset-password/375afe1104f4a487a73823c50a9292a2
```

**最大影响**: 敏感数据泄漏（获取challenge 7的flag）

</details>

### Authentication Bypass (CWE-287, 6 条)

| # | 严重度 | 文件:行 | 入口路由 | 简短描述 |
|---:|---|---|---|---|
| 1 | High | `Assignment8.java:42` | `/challenge/8/vote/{stars}` | [发现] vote()方法上标注了@GetMapping注解，限制了只接受GET请求，但方法内部在第46行又检查请求方法是否为GET并返回需要登录的错误。这种设计存在逻辑矛盾，并且可能被攻击者绕过。  [攻击面] 该方法使用@GetMapp |
| 2 | High | `SigningAssignment.java:57` | `/crypto/signing/verify` | [发现] 在 `/crypto/signing/verify` 接口的 `completed()` 方法中，第 57 行开始的逻辑存在问题。当 `tempModulus` 长度为 512 时，会添加前缀 "00" 进行模数匹配，但后续调用  |
| 3 | High | `JWTRefreshEndpoint.java:91` | `/JWT/refresh/checkout` | [发现] 在 JWTRefreshEndpoint.java 的 checkout 方法中，JWT 解析使用了 setSigningKey 但实际对 alg=none 缺少全面防御。第 95 行仅对 Tom 用户的 alg=none 做了处 |
| 4 | High | `JWTSecretKeyEndpoint.java:38` | `/JWT/secret` | [发现] JWT 密钥生成逻辑存在缺陷：第 37-38 行使用硬编码的字符串数组 SECRETS 生成 JWT 密钥，且密钥每次重启后会变化，但攻击者可通过暴力破解尝试所有可能的密钥值（数组长度仅为 5），从而伪造有效的 JWT 令牌绕过身 |
| 5 | High | `JWTVotesEndpoint.java:189` | `/JWT/votings` | [发现] JWT密钥硬编码为"victory"的Base64编码（JWT_PASSWORD字段），攻击者可伪造包含"admin":"true"的JWT令牌绕过鉴权，调用resetVotes接口重置投票。  [攻击面] 利用硬编码的JWT密钥 |
| 6 | High | `JWTHeaderJKUEndpoint.java:49` | `/JWT/jku/delete` | [发现] JWT 验证过程中未对 JKU 头部声明进行安全校验，允许攻击者指定任意 JKU 地址提供恶意 JWK 公钥，从而实现 JWT 伪造与身份绕过。  [攻击面] 攻击者可以通过伪造 JWT，在 jku 声明中指定自己控制的服务器地址 |

<details>
<summary>展开样例 (JWTHeaderJKUEndpoint.java): PoC + 修复建议</summary>

**攻击向量**: 该方法使用@GetMapping注解限制了只接受GET请求，但内部第46行又检查请求方法是否为GET并返回需要登录的错误，这种逻辑矛盾可能导致认证绕过。攻击者可以使用其他HTTP方法（如POST、PUT、DELETE等）来访问该接口，从而绕过登录检查直接投票。

**PoC payload**:
```
发送HTTP POST请求到 /challenge/8/vote/5 即可绕过登录检查，直接投票。
```

**最大影响**: 攻击者可以绕过登录检查直接进行投票操作，可能导致投票结果被操纵。

</details>

### Race Condition (CWE-362, 6 条)

| # | 严重度 | 文件:行 | 入口路由 | 简短描述 |
|---:|---|---|---|---|
| 1 | Medium | `UserService.java:40` | `/register.mvc` | [发现] UserService.addUser()方法在第42行检查用户是否已存在，但第43行直接调用save()保存新用户，存在TOCTOU（Time of Check to Time of Use）并发条件竞争问题。当两个线程同时注册 |
| 2 | Medium | `UserService.java:41` | `/login-oauth.mvc` | [发现] UserService.addUser方法（第41-43行）中，存在并发竞争条件：首先查询用户是否存在（userRepository.existsByUsername），然后直接保存用户（userRepository.save）， |
| 3 | Medium | `Assignment8.java:51` | `/challenge/8/vote/{stars}` | [发现] 第 42 行 vote() 方法对共享 HashMap votes 执行 read-modify-write 操作（第 51-52 行）时未加锁或使用并发安全集合，并发投票可能导致投票数统计不正确；且第 46 行的动词鉴权逻辑有误 |
| 4 | Medium | `CIAQuiz.java:22` | `/cia/quiz` | [发现] 第 22 行定义的 guesses 数组是控制器的成员变量，属于共享状态。当多个用户并发访问 /cia/quiz 端点时，POST 请求会修改 guesses 数组，GET 请求会读取该数组，由于未加任何同步锁，会导致并发访问下的 |
| 5 | Medium | `JWTQuiz.java:24` | `/JWT/quiz` | [发现] JWTQuiz类中的guesses数组是共享实例变量，completed()方法在多线程环境下对其进行写入操作（第36行和第39行），但没有任何同步机制（如synchronized关键字或Lock）保护该共享变量，存在并发修改导致 |
| 6 | High | `JWTRefreshEndpoint.java:131` | `/JWT/refresh/newToken` | [发现] 第131行validRefreshTokens.contains(refreshToken)和第132行validRefreshTokens.remove(refreshToken)组成的read-modify-write序列没有 |

<details>
<summary>展开样例 (JWTRefreshEndpoint.java): PoC + 修复建议</summary>

**攻击向量**: 通过并发发送大量相同用户名的注册请求，利用TOCTOU竞争条件绕过用户存在性检查，实现重复注册。

**PoC payload**:
```
使用并发请求工具（如Apache Bench、JMeter或Python脚本）向/register.mvc发送包含相同username和password参数的POST请求，观察是否创建了重复用户。
```

**最大影响**: 导致数据不一致，可能影响应用的正常功能，如用户登录、权限管理等。

</details>

### Insufficient Anti-Automation (CWE-307, 4 条)

| # | 严重度 | 文件:行 | 入口路由 | 简短描述 |
|---:|---|---|---|---|
| 1 | Medium | `ResetLinkAssignment.java:65` | `/PasswordReset/reset/login` | [发现] 第 65-78 行 login 方法对登录失败无任何防暴破机制（无重试次数限制、无间隔控制、无验证码），攻击者可通过无限次请求暴力破解密码  [攻击面] 攻击者可以通过构造大量 HTTP 请求，对 /PasswordReset/r |
| 2 | Medium | `TriedQuestions.java:18` | `/PasswordReset/SecurityQuestions` | [发现] TriedQuestions.java:18 中的 incr() 方法无任何限速、防暴破或锁定机制，攻击者可通过无限次请求快速遍历所有可能的安全问题，从而获取敏感信息。  [攻击面] 攻击者可通过自动化脚本向 /PasswordR |
| 3 | Medium | `JWTController.java:20` | `/jwt` | [发现] JWTController 中的 /jwt 路由（第20行）和 /jwt/decode、/jwt/encode 子路由（第29行、第40行）均未配置任何限流机制（无 @RateLimit 注解、无 Token 桶/滑动窗口等限流逻 |
| 4 | Medium | `MailboxController.java:42` | `/WebWolf/mail` | [发现] WebWolf 的邮件发送接口 /mail（POST 方法）在 WebSecurityConfig.java 第 44 行中被配置为 permitAll()（完全允许匿名访问），并且在 MailboxController.java |

<details>
<summary>展开样例 (MailboxController.java): PoC + 修复建议</summary>

**攻击向量**: 攻击者可以通过构造大量 HTTP 请求，对 /PasswordReset/reset/login 接口进行暴力破解。由于该接口无防暴破机制，攻击者可通过无限次尝试来猜测密码。其中 email 参数固定为 tom@webgoat-cloud.org，password 参数为攻击者猜测的密码，username 参数可由攻击者控制或通过其他方式获取。

**PoC payload**:
```
POST /PasswordReset/reset/login HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded

password=test123&email=tom@webgoat-cloud.org&username=attacker
```

**最大影响**: 攻击者可通过暴力破解获取 Tom 用户的密码，进而成功登录系统，可能导致敏感信息泄露或进一步的攻击。

</details>

### Hardcoded Credentials (CWE-798, 3 条)

**PoC payload**:
```
GET /clientSideFiltering/salaries HTTP/1.1
Host: localhost:8080
```

**最大影响**: 敏感信息泄露（泄露用户的 SSN 和薪资等个人敏感数据）

</details>

---

## 附录

### A. 漏洞条目完整字段说明

每条 `reports/vulnerability_*.json` 含以下字段(由 BlueValidator 输出 → state_router 映射):

```json
{
  "task_id": "TASK-INIT-001_SINK_82_TRACE_xxx",
  "timestamp": "2026-05-15T15:52:38",
  "vuln_type": "SQL Injection",     // 上游 Semgrep metadata.vuln_class 或 LogicAuditor 白名单
  "cwe_id": "CWE-89",                 // 由 classify.py 静态映射
  "severity": "High",                 // 由 classify.py 默认表 + max_impact 启发
  "location": { "file": "...", "line": 47 },
  "entry_route": "/SqlInjection/attack3",
  "confidence": "MEDIUM",             // 来自 Semgrep rule metadata.confidence
  "call_chain": ["1. Controller", "2. Service", "3. Sink"],
  "description": "...",              // 来自 suspicion_reason
  "attack_vector": "...",            // RedValidator EXPLOITABLE 时填
  "poc_payload": "...",              // RedValidator EXPLOITABLE 时填
  "max_impact": "...",               // RedValidator EXPLOITABLE 时填
  "defense_analysis": "...",         // BlueValidator 路径 A 复核结果
  "mitigation_advice": "..."         // BlueValidator 修复建议
}
```

### B. 数据导出工具

如需把全部 133 条漏洞按其他维度(如按文件 / 按 entry_route / 按 confidence)重新汇总,可:

```bash
# 按文件统计
ls reports/*.json | xargs -I{} python3 -c \
  "import json;d=json.load(open('{}'));l=d.get('location',{{}});print(l.get('file',''))" 2>/dev/null \
  | sort | uniq -c | sort -rn

# 按 entry_route 统计
ls reports/*.json | xargs -I{} python3 -c \
  "import json;d=json.load(open('{}'));print(d.get('entry_route',''))" 2>/dev/null \
  | sort -u | grep -v ^/home
```

### C. 完整漏洞 JSON 文件位置

- 汇总 Markdown: `reports/SUMMARY.md`
- 详细 JSON: `reports/vulnerability_*.json` (共 133 个文件)
- 历史 baseline 归档:
  - `reports_baseline_2026-05-11/` (7 条)
  - `reports_full_baseline_2026-05-12_67vuln/` (67 条)
  - `reports_pathtraversal_only_2026-05-12/` (45 条)
  - `reports_v10_baseline_2026-05-15_105vuln/` (105 条)
  - `reports_v11_baseline_2026-05-15_117vuln/` (117 条)
  - `reports_v12_baseline_2026-05-15_127vuln/` (127 条)
  - `reports_v8_baseline_2026-05-13_122vuln/` (122 条)
  - `reports_v9_baseline_2026-05-14_92vuln/` (92 条)

---

*本扫描报告由 CodeAudit 多智能体引擎自动生成,详细技术演进见 [REPORT.md](REPORT.md)。*
