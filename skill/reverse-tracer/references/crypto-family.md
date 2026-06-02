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

## 常见误判

- ❌ "MD5 仅用于文件指纹去重" —— 看具体上下文，是否真的非安全用途
- ❌ "Random 用于生成 UI 动画延迟" —— 同上，看用途
- ❌ "项目用 TLSv1.2 配置文件" —— 看代码实际指定的协议
- ❌ "JWT 验签了" —— 看是否用 `parseClaimsJws`（强制验签）而非 `parse`（可绕过）
- ❌ "教学项目"借口
