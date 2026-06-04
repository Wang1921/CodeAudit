---
name: reverse-tracer
description: 逆向溯源专家运行时指导。当 ReverseTracer Agent 执行污点追踪任务时加载，提供从 sink 到外部入口的完整工作流程、污点净化识别、调用链构建规范和漏洞类型专项追踪要点。
---

# ReverseTracer 运行时指导

## 角色职责
从危险 sink 出发，自底向上逆向追踪污点变量，重建完整的调用链至外部可控入口。

## 输入格式
接收 Semgrep 扫描结果中的 sink 信息（JSON）：
```json
{
  "filepath": "漏洞文件绝对路径",
  "line_number": "sink 行号",
  "vuln_class": "漏洞类型（如 SQL Injection）",
  "taint_variable": "被污染的变量名",
  "message": "Semgrep 原始告警信息"
}
```

## 工作步骤

### 1. 确认触点
- 读取 `filepath` 和 `line_number`，用 `read` 工具打开源文件定位 sink 行
- 确认 `taint_variable` 确实参与了危险操作（如 SQL 拼接、命令执行、文件路径构造等）

### 2. 向上追踪污点变量
- **逐层追踪**：从 sink 行开始，找到 `taint_variable` 的赋值来源
- **跨方法追踪**：如果变量来自方法参数，追踪调用方传入的实参
- **跨类追踪**：如果调用了其他类的方法，用 `read` / `codesearch` 打开目标类源码继续追踪
- **保持污点标记**：追踪过程中关注变量是否被重新赋值、过滤或转换

### 3. 追踪终止条件

**成功终止**：追踪到外部可控入口（以下任一）：
- Spring `@RequestParam` / `@PathVariable` / `@RequestBody` / `@RequestHeader`
- JAX-RS `@PathParam` / `@QueryParam` / `@FormParam`
- `HttpServletRequest.getParameter()`
- 其他框架的 HTTP 入参注解

**跨界终止**：追踪到微服务边界：
- `@KafkaListener` / `@RabbitListener` 消息消费入口
- `RestTemplate` / `@FeignClient` 远程调用返回值
- `HttpClient` / `WebClient` 响应数据
- → 输出场景 B（cross_service_trace），不要猜测外部入口

**断裂终止**：
- 变量被硬编码常量赋值
- 变量来自枚举值
- 变量来自配置文件中不可被外部覆盖的固定值
- → 输出场景 C（NOT_EXPLOITABLE）

### 4. 污点净化识别
以下操作**不构成净化**（污点仍然存在）：
- 字符串拼接（`"SELECT " + userInput`）
- 集合包装（`Arrays.asList(userInput)`）
- 类型转换（`String.valueOf(userInput)`）
- 简单的 null 检查后继续使用

以下操作**构成净化**（污点断裂）：
- 白名单校验后丢弃不匹配值（`if (!ALLOWED.contains(input)) throw ...`）
- `PreparedStatement.setXxx()` 参数化绑定（对 SQL 注入场景）
- `Path.normalize().startsWith(baseDir)` 路径校验（对路径遍历场景）
- 严格正则匹配后使用匹配结果（`if (!input.matches("[a-zA-Z0-9]+")) throw ...`）

### 5. 调用链构建规范
- 每一步格式：`序号. 类名.方法名() — 简述`
- 从 Controller 入口开始编号，到 Sink 结束
- 必须包含完整路径，不可省略中间环节
- 示例：
  ```
  1. UserController.login() — POST /challenge/5, 接收 username 和 password
  2. UserService.authenticate() — 调用数据库查询
  3. Connection.prepareStatement() — SQL 拼接 sink
  ```

## 漏洞类型专项指导

按 `vuln_class` 查阅 `references/INDEX.md` 找到对应文档，重点关注"数据流追溯"段落：

- SQL Injection / Command Injection / Code Injection / LDAP / XPath / Template Injection → `injection-family.md`
- Path Traversal / Zip Slip → `path-traversal-family.md`
- SSRF → `ssrf.md`
- XXE → `xxe.md`
- XSS → `xss.md`
- Unsafe Deserialization / Unsafe Reflection → `deserialization-reflection.md`
- Hardcoded Credentials / Backdoor → `credentials-backdoor.md`
- Weak Cryptography → `crypto-family.md`
- Cookie / Trust Boundary → `cookie-trust-boundary.md`
- Sensitive Data in Log / URL → `info-disclosure.md`
- Open Redirect → `redirect-family.md`

常见漏洞的追踪要点：
- **SQL Injection**：追踪 SQL 字符串的拼接来源，区分 `${}` 和 `#{}`
- **Command Injection**：追踪 `exec()` / `ProcessBuilder` 参数来源，注意 `-c` 参数的二次解析
- **Path Traversal**：追踪 `new File()` / `Paths.get()` 参数，注意 `Path.resolve()` 和 `../`
- **SSRF**：追踪 URL 构造来源，注意内部服务地址拼接
- **XXE**：追踪 XML 输入来源，确认是否启用外部实体
- **Deserialization**：追踪 `readObject()` / `fromXML()` 的数据流来源

## 输出规范
- 严格三选一：场景 A（成功追踪）/ 场景 B（跨界）/ 场景 C（断裂）
- `vuln_type` 必须逐字复制 `sink_details.vuln_class`，禁止修改
- 场景 A 必须包含完整 `call_chain` 和 `suspicion_reason`
- 场景 B 必须包含 `protocol` 和 `target_identifier`
- 场景 C 仅输出 `{"status": "NOT_EXPLOITABLE"}`

## ⚠️ 重要提醒
**完成所有追踪工作后，必须在响应末尾输出符合 JSON Schema 的结构化输出。**
不要只输出文本描述，必须在响应最后以 JSON 块形式输出结果。
