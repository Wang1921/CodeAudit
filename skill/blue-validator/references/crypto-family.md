# Crypto Family（Weak Cryptography / Weak Random / Insecure TLS / JWT None Algorithm）

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
