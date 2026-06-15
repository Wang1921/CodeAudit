---
name: reverse-tracer
description: 逆向溯源专家运行时指导。当 ReverseTracer Agent 执行污点追踪任务时加载，提供从 sink 到外部入口的完整工作流程、污点净化识别、调用链构建规范和输出场景规范。
---

# ReverseTracer 运行时指导

## 角色职责
用codegraph从危险 sink 出发，自底向上逆向追踪污点变量，重建完整的调用链至外部可控入口。

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
- 用 codegraph 打开 `filepath`，定位 `line_number`
- 确认 `taint_variable` 确实参与了危险操作（如 SQL 拼接、命令执行、文件路径构造等）

### 2. 向上追踪污点变量
- **必须用 codegraph 读取代码**：打开上游方法的源码分析变量赋值来源，禁止仅凭方法名推断
- **逐层追踪**：从 sink 行开始，找到 `taint_variable` 的赋值来源
- **跨方法追踪**：如果变量来自方法参数，用 codegraph 追踪调用方传入的实参
- **跨类追踪**：如果调用了其他类的方法，用 codegraph 打开目标类源码继续追踪
- **保持污点标记**：追踪过程中关注变量是否被重新赋值、过滤或转换

### 3. 追踪终止条件

**成功终止**：追踪到外部可控入口（以下任一）：
- Spring `@RequestParam` / `@PathVariable` / `@RequestBody` / `@RequestHeader`
- JAX-RS `@PathParam` / `@QueryParam` / `@FormParam`
- `HttpServletRequest.getParameter()`
- 其他框架的 HTTP 入参注解

⚠️ **以下不是 HTTP 入口，必须走跨界终止**：
- `@KafkaListener` / `@RabbitListener` / `@JmsListener` → 数据来自其他微服务的生产者，无法在本服务内追溯原始外部入口
- 遇到消息消费入口时，不要把它当作场景 A 的外部可控入口输出，必须输出场景 B

**跨界终止**：追踪到微服务边界：
- `@KafkaListener` / `@RabbitListener` / `@JmsListener` 消息消费入口
- `RestTemplate` / `@FeignClient` 远程调用返回值
- `HttpClient` / `WebClient` 响应数据
- → 输出场景 B（cross_service_trace），不要猜测外部入口

**断裂终止**：
- 变量被硬编码常量赋值
- 变量来自枚举值
- 变量来自配置文件中不可被外部覆盖的固定值
- → 输出场景 C（NOT_EXPLOITABLE）

### 4. 污点净化识别
**必须用 codegraph 读取代码确认**，不能仅凭方法名推断净化逻辑的存在。

以下操作**不构成净化**（污点仍然存在）：
- 字符串拼接（`"SELECT " + userInput`）
- 集合包装（`Arrays.asList(userInput)`）
- 类型转换（`String.valueOf(userInput)`）
- 简单的 null 检查后继续使用

以下操作**构成净化**（污点断裂）：
- **必须用 codegraph 验证代码确实存在**：确认过滤/绑定逻辑实际出现在代码中
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

## 输出规范

严格三选一：场景 A（成功追踪到外部入口）/ 场景 B（追踪到微服务边界）/ 场景 C（链路断裂）。

### 场景 A：成功追踪

追踪到 HTTP 外部可控入口（如 `@RequestParam` / `@PathVariable` / `HttpServletRequest.getParameter()` 等）。
**消息消费入口（`@KafkaListener` 等）不属于场景 A**，即使消息内容攻击者可控，也应输出场景 B 让引擎跨服务追踪到生产者。

```json
{
  "vuln_type": "逐字复制 sink_details.vuln_class，禁止修改",
  "entry_route": "外部入口的 API 路径（如 POST /api/login）",
  "filepath": "sink 所在文件绝对路径",
  "line_number": "sink 行号",
  "call_chain": [
    "1. Controller.method() — 简述",
    "2. Service.method() — 简述",
    "3. SinkClass.method() — sink 简述"
  ],
  "suspicion_reason": "引用具体代码行说明污点如何从外部入口流到 sink"
}
```

- `call_chain` 必须完整，从入口到 sink 不可省略中间环节
- `suspicion_reason` 必须引用具体代码行或片段作为证据
- 不得输出 `status` 字段

### 场景 B：跨界追踪

追踪到微服务边界（如 `@KafkaListener` / `@FeignClient` / `RestTemplate` 等），无法在当前服务内确认外部入口。

```json
{
  "action": "cross_service_trace",
  "vuln_type": "逐字复制 sink_details.vuln_class，禁止修改",
  "protocol": "调用协议（HTTP / Kafka / RabbitMQ / gRPC 等）",
  "target_identifier": "目标服务标识（Feign 接口名 / URL 模板 / topic 名等）",
  "taint_variable": "跨服务传递的污点变量名"
}
```

- 不得输出 `call_chain` / `entry_route` 等场景 A 字段
- 引擎收到后会自动在其他微服务中并发启动溯源 Agent

### 场景 C：链路断裂

污点变量被硬编码常量、枚举值或不可被外部覆盖的配置固定值赋值，追踪无法继续。

```json
{
  "status": "NOT_EXPLOITABLE",
  "break_reason": "说明断裂原因（≥20 字符），如：变量被硬编码常量赋值 / 来自枚举值 / 来自不可外部覆盖的配置固定值"
}
```

- `break_reason` 必须 ≥ 20 字符，说明断裂的具体原因
- 不得输出 `vuln_type` / `entry_route` / `call_chain` / `action` 等业务字段

### 互斥约束

- 三个场景严格互斥，不可混合输出
- 同时输出 DEFENDED 和 call_chain / entry_route 视为矛盾，下游直接丢弃

## ⚠️ 重要提醒
**完成所有追踪工作后，必须在响应末尾输出符合 JSON Schema 的结构化输出。**
不要只输出文本描述，必须在响应最后以 JSON 块形式输出结果。
