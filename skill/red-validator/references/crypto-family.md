# Crypto Family（Weak Cryptography / Weak Random / Insecure TLS / JWT None Algorithm）

## 误判案例

| 防御手段 | 误判场景 | 为什么安全 |
|---|---|---|
| bcrypt / scrypt / Argon2 | `BCrypt.hashpw(password, BCrypt.gensalt(12))` | 慢哈希 + 自适应 cost，暴力破解成本极高 |
| AES-GCM | `Cipher.getInstance("AES/GCM/NoPadding")` | 认证加密，防篡改 + 机密性 |
| SecureRandom | `SecureRandom.getInstanceStrong()` | 密码学安全随机数，不可预测 |
| TLS 1.2+ / 证书校验 | `SSLContext.getInstance("TLSv1.2")` + 有效证书链验证 | 传输加密 + 身份认证 |
| JWT RS256 + 严格校验 | `Jwts.parser().setSigningKey(publicKey).parseClaimsJws(token)` + 校验 issuer/audience/exp | 非对称签名 + 完整 claims 校验 |
| HMAC-SHA256 签名 | `Mac.getInstance("HmacSHA256")` + 足够长密钥 | 对称签名，密钥安全时不可伪造 |
| key derivation function | `PBKDF2WithHmacSHA256` + 高迭代次数 | 派生密钥，暴力破解成本高 |
| 证书钉扎 (Certificate Pinning) | 客户端校验特定证书指纹 | 中间人无法用合法证书替换 |

## 绕过案例

| 看似防御 | 绕过思路 | 示例 |
|---|---|---|
| MD5 / SHA-1 密码哈希 | 彩虹表 / hashcat 字典攻击 | 常见密码 5 分钟内破解，无盐时查彩虹表秒出 |
| DES / 单 DES | 64-bit 密钥穷举 | EFF 专用硬件几小时穷举 |
| AES/ECB 模式 | 块复用攻击 | 同明文块 → 同密文块，频率分析泄露模式信息 |
| 弱 RSA 1024 | 大整数分解 | 学术/国家级算力可分解 |
| `java.util.Random` 做 session ID | 可预测随机序列 | 已知一个 `nextLong()` 输出可推算全部序列 |
| 空 TrustManager | 接受任意证书 | MITM 截获 + 注入恶意服务端响应 |
| JWT alg=none | 服务器未强制校验算法 | header `{"alg":"none"}` + 删签名 → 伪造任意 claim |
| JWT 密钥硬编码 | 源码泄露后可签发 token | 拿到 `SECRET` → 自签 admin token |
| JWT JKU/X5U 头 | 服务器从外部 URL 拉取公钥 | `"jku":"http://attacker/jwk.json"` — 用自己的公钥签名 |
| AES/CBC 无 HMAC | Padding Oracle Attack | 逐字节爆破明文，无需知道密钥 |
| 静态 IV | 相同明文 + 相同密钥 = 相同密文 | 首块密文相同，泄露信息 |
| SHA-256 无盐 | 相同密码 = 相同哈希 | 查表 / 彩虹表匹配 |
| `SSLContext.getInstance("TLS")` 默认配置 | 允许弱协议/弱套件 | JDK 默认可能协商 TLS 1.0 / 弱 cipher |
| 自签名证书无校验 | 客户端忽略证书验证 | `trustAllCerts` — MITM 可替换任意证书 |
