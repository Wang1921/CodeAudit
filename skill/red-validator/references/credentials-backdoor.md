# Credentials & Backdoor Family（Hardcoded Credentials / Hardcoded Backdoor）

## 区别

| | Hardcoded Credentials | Hardcoded Backdoor |
|---|---|---|
| 形态 | **变量赋值**层面 | **业务判定**层面 |
| 例子 | `String password = "admin123"` | `if (input.equals("admin123")) return success()` |
| 风险 | 被泄露后任意人可用 | 知道字面量即可绕过认证 |

## 误判案例

| 防御手段 | 误判场景 | 为什么安全 |
|---|---|---|
| 环境变量注入 | `String dbPass = System.getenv("DB_PASSWORD")` | 密码不存源码，由部署环境注入 |
| 配置中心 / Vault | `vault.read("secret/db/password")` | 密码存外部密钥管理系统，代码中无明文 |
| 占位符配置 | `spring.datasource.password=${DB_PASSWORD}` | 框架运行时从环境变量/配置中心解析，源码无明文 |
| 默认密码 + 首次强制修改 | 首次登录必须重置密码 | 默认密码在修改后失效 |
| 硬编码但仅限测试环境 | `@Profile("test")` 下的测试专用密码 | 生产环境不加载该 Profile，密码不生效 |
| 硬编码的公钥 | `String PUB_KEY = "MIIBIjAN..."` | 公钥非秘密信息，泄露不影响安全 |
| 硬编码但功能只读 | 数据库连接只有 SELECT 权限 | 即使密码泄露也无法修改数据 |

## 绕过案例

| 看似防御 | 绕过思路 | 示例 |
|---|---|---|
| 硬编码 JWT Secret | 源码泄露即可签发任意 token | 拿到 `SECRET_KEY = "myJwtSecret"` → 自签 `admin=true` claim |
| 硬编码数据库密码 | 直接连数据库 | 密码在源码中 → 如果数据库网络可达即可直连 |
| 硬编码 API Key | 用该 Key 调用第三方服务 | Stripe / Twilio / AWS Key → 产生账单或数据泄露 |
| 硬编码 Backdoor 密码 | 直接输入硬编码字面量 | `if (input.equals("superSecret123")) loginAsAdmin()` → 输入 `superSecret123` |
| Fallback Backdoor | 触发 DB 连接失败 | 拒绝服务 / 网络隔离使 DB 不可用 → 进入 fallback 硬编码认证 |
| 配置文件中的密码 | 配置文件也属源码 | `application.yml` 中 `password: admin123` — 等同于硬编码 |
| 硬编码加密密钥 | 密钥泄露 = 加密无意义 | `String AES_KEY = "1234567890abcdef"` — 拿到密钥解密所有数据 |
| 硬编码但注释"仅用于开发" | 生产部署忘记删除 | 开发后门留在生产代码中，攻击者审计代码发现 |
| 硬编码内网服务 Token | 内网渗透后直接使用 | 攻击者进入内网 → 用硬编码 Token 调用内部微服务 |
