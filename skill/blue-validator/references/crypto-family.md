# Crypto Family（Weak Cryptography / Weak Random / Insecure TLS / JWT None Algorithm）

## sink 模式速查

### Weak Cryptography
- `Cipher.getInstance("DES" / "DESede" / "RC2" / "RC4" / "Blowfish" / "AES/ECB/...")` —— 弱算法/弱模式
- `MessageDigest.getInstance("MD5" / "MD2" / "SHA-1")` —— 弱哈希
- `KeyPairGenerator.getInstance("RSA").initialize(512 / 1024)` —— 短 RSA 密钥
- `KeyGenerator.getInstance("DES" / "RC4")` 等
- `Mac.getInstance("HmacMD5" / "HmacSHA1")`
- `Signature.getInstance("MD5withRSA" / "SHA1withRSA" / "NONEwith*")`
- `new ECGenParameterSpec("secp160r1" / "secp192r1")` —— < 224 位 EC 曲线
- Bouncy Castle: `new RC4Engine() / DESEngine() / BlowfishEngine()`
- `DigestUtils.md5/md5Hex/sha1/sha1Hex(...)` (Apache Commons Codec)
- 自定义 XOR "加密"循环

### Weak Random
- `new Random()` / `Random.nextXxx()` —— 线性同余，可预测
- `Math.random()` —— 同上
- `ThreadLocalRandom` —— 用于安全用途不安全
- `RandomStringUtils.random*(len)` (Apache Commons Lang) —— 默认用 Random
- `SecureRandom.getInstance("SHA1PRNG")` —— 弱实现，应该用无参 `new SecureRandom()`

### Insecure TLS
- `TrustManager` 实现里 `checkClientTrusted/checkServerTrusted` 空方法（接受任意证书）
- `HostnameVerifier.verify(...)` 返回 `true`（不验主机名）
- `HttpsURLConnection.setDefaultHostnameVerifier((h,s)->true)`
- `SSLContext.getInstance("SSL" / "TLSv1" / "TLSv1.1")` —— 弃用协议
- `OkHttpClient.Builder().hostnameVerifier(...)` 自定义不验

### JWT None Algorithm
- `Jwts.parser().parse(token)` 后**没有**调 `.setSigningKey()` —— 接受 alg=none
- `Jwts.parserBuilder().build().parse(...)` 同上
- 自定义 JWT 实现里没拒绝 alg=none

## 数据流追溯重点

弱算法/弱随机/弱 TLS 是**静态定性 sink**（fast-path），不需要追污点。看代码本身即可定罪：
- 算法字符串字面量为弱算法 → VULNERABLE
- TrustManager 实现内为空 → VULNERABLE
- JWT 解析没绑定 signing key → VULNERABLE

仅当 sink 是"安全相关"才算漏洞：
- `MessageDigest.getInstance("MD5")` 用于密码哈希 → VULNERABLE
- 同样代码用于非安全场景（如生成文件指纹做去重）→ 边缘 / 业务可接受

## 防御机制速查

### 推荐加密算法
- 对称加密：`AES/GCM/NoPadding` 或 `AES/CBC/PKCS5Padding` + 随机 IV
- 哈希：`SHA-256` / `SHA-384` / `SHA-512` / `SHA3-256` / `BCrypt/Argon2`（密码哈希专用）
- HMAC：`HmacSHA256` / `HmacSHA512`
- 签名：`SHA256withRSA` / `SHA256withECDSA` / `Ed25519`
- 密钥长度：RSA ≥ 2048, EC ≥ secp256r1

### 安全随机
- `new SecureRandom()` 无参（用平台最强 RNG）
- 避免 `SHA1PRNG` 明确指定

### TLS
- `SSLContext.getInstance("TLSv1.2")` 或 `"TLSv1.3"`
- 用默认 TrustManager + HostnameVerifier，**不要重写为空实现**

### JWT
```java
Jwts.parserBuilder()
    .setSigningKey(secretKey)        // 必须设置
    .build()
    .parseClaimsJws(token);          // 必须用 parseClaimsJws（强制验签）
```

## 常见误判

- ❌ "MD5 仅用于文件指纹去重" —— 看具体上下文，是否真的非安全用途
- ❌ "Random 用于生成 UI 动画延迟" —— 同上，看用途
- ❌ "项目用 TLSv1.2 配置文件" —— 看代码实际指定的协议
- ❌ "JWT 验签了" —— 看是否用 `parseClaimsJws`（强制验签）而非 `parse`（可绕过）
- ❌ "教学项目"借口

## 证据引用范例

**DEFENDED 时**：
```
defense_analysis: "Line 38 String hash = DigestUtils.sha256Hex(content);
                  — 用于文件去重(line 36 注释 'compute content fingerprint for dedup'),
                  非密码哈希用途,SHA-256 在文件指纹场景安全充足."
```

**VULNERABLE 时**：
```
suspicion_reason: "Line 39 String passwordHash = DigestUtils.md5Hex(password);
                  Line 41 user.setPasswordHash(passwordHash);  // 存数据库
                  — MD5 已被破解,且无 salt,彩虹表 1 秒内可碰撞.
                  密码哈希应用 BCrypt/Argon2."
```

## PoC 模板

| 弱点 | 攻击思路 |
|---|---|
| MD5 / SHA-1 密码 | 彩虹表 / hashcat 字典攻击 (5 分钟内破常见密码) |
| DES / 单 DES | DES 64-bit 密钥 EFF 几小时穷举 |
| AES/ECB | 块复用攻击 / 频率分析（同明文 → 同密文） |
| 弱 RSA 1024 | 大整数分解（学术/国家级算力） |
| 弱随机 session ID | 重放 + 预测 nextLong() 序列（已知一个种子推全部） |
| 空 TrustManager | MITM 截获 + 注入恶意服务端响应 |
| JWT alg=none | 把 header alg 改 none + 删 signature 即可伪造任意 claim |
| JWT 密钥硬编码 | 拿到源码即可签发任意 admin token |
| JWT JKU 头 | 将 jku 指向攻击者控制的 JWK 服务器，自签 token |
