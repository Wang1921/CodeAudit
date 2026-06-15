# SSRF (Server-Side Request Forgery, CWE-918)

## 误判案例

| 防御手段 | 误判场景 | 为什么安全 |
|---|---|---|
| URL 白名单 | `if (!ALLOWED_HOSTS.contains(host)) throw ...` | 只允许预定义域名，内网 IP 无法通过 |
| 禁止内网 IP | 正则/InetAddress 判断目标 IP 是否为私有地址 | 10.x / 172.16-31.x / 192.168.x / 127.x 被拦截 |
| 禁止非 HTTP 协议 | `if (!url.startsWith("http://") && !url.startsWith("https://")) throw ...` | `file://` / `gopher://` / `dict://` 无法通过 |
| 响应内容过滤 | 仅返回特定 Content-Type 或限长 | 即使请求成功，敏感信息被过滤 |
| 出站防火墙 | 服务器无法访问内网其他服务 | 网络层阻断，代码层防御只是补充 |

## 绕过案例

| 看似防御 | 绕过思路 | 示例 |
|---|---|---|
| URL 白名单只检查域名 | `@` 符号欺骗 | `http://whitelist.com@evil.com/` — 实际访问 evil.com |
| 白名单域名但允许子域名 | 攻击者控制子域名 | `http://evil.whitelist.com/` — DNS 解析到攻击者 IP |
| 禁止内网 IP 但不校验解析结果 | DNS rebinding | 第一次解析返回公网 IP（通过校验），第二次返回 127.0.0.1（实际请求） |
| 禁止内网 IP 但允许重定向 | 302 跳转到内网 | 请求 `http://evil.com/redirect` → 302 到 `http://127.0.0.1:6379/` |
| 禁止 127.0.0.1 但未覆盖等价写法 | 短 IP / 十六进制 / 八进制 | `0x7f000001` / `0177.0.0.1` / `2130706433` / `[::1]` |
| 只检查 URL 字符串 | URL 解析差异 | `http://evil.com#@whitelist.com` — 不同解析器对 `#` 和 `@` 处理不同 |
| 禁止 file:// 但支持其他协议 | gopher / dict 攻击内网 | `gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall` — 构造 Redis 命令 |
| 云环境元数据 | 169.254.169.254 不在内网黑名单 | `http://169.254.169.254/latest/meta-data/iam/security-credentials/` — 获取 AWS 凭据 |
| URL 双编码 | WAF / 过滤器只解码一次 | `http://evil%2540whitelist.com` — 第一次解码 `evil%40whitelist.com`，第二次 `evil@whitelist.com` |
| IPv6 映射地址 | `[::ffff:127.0.0.1]` | 部分校验只处理 IPv4，IPv6 映射地址绕过 |
