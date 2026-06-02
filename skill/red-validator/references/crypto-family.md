# Crypto Family（Weak Cryptography / Weak Random / Insecure TLS / JWT None Algorithm）

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
