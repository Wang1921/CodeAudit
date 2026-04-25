# DEFENDED 证据规范

判定 Semgrep 发现是真实漏洞（VULNERABLE）还是上下文中安全（DEFENDED）的硬性规则。
在 skill 工作流的阶段 5 应用。

---

## ✅ 允许的 DEFENDED 证据（必须引用代码行号 / 片段）

仅当至少满足下列代码级事实之一**且**裁决文本引用了具体的行号或代码片段时，
才能把发现标为 **DEFENDED**：

1. **死代码**
   sink 所在的函数 / 分支不可达：
   - 整个仓库 grep 不到调用方
   - 位于永假分支内（`if (false)` / `if (DEBUG && ...)`）
   - 标了 `@Deprecated` 且方法体为空

2. **下游覆盖**
   sink 紧跟一条把危险值替换为安全值的语句。
   例：`KeyGenerator.getInstance("DES")` 拿到的 key 在加密调用前已被
   `KeyGenerator.getInstance("AES").generateKey()` 重新赋值。

3. **场景明确不敏感**
   `new Random()` 等输出明显**仅**用于 UI 动画 / 测试数据 / 非安全场景的随机抽样，
   绝不参与任何安全决策。需要引用消费它的具体调用，并证明该调用与安全无关。

4. **SDK 内部协商参数**
   该"弱算法"字符串只是协议协商时传给远端的参数（不参与本地加密 / 解密 / 哈希），
   远端会做最终选择。例：TLS 密码套件白名单声明。

5. **输出已脱敏**（适用 sensitive-data-in-log / -url / stack-trace-exposure 等）
   sink **之前**已应用过遮蔽 / 脱敏逻辑（`mask` / `substring(0,4)+"****"` /
   `MaskingPatternLayout` / 自定义 `Converter`）。需要引用脱敏代码的位置。

6. **环境隔离**
   sink 被 `@Profile("dev"|"test")` / `@ActiveProfiles(...)` /
   `@ConditionalOnProperty` / Spring `Condition` / Maven Profile 包裹，
   生产构建无法到达该代码。**必须引用具体注解 / 条件名**。

7. **数据本身非敏感**（适用 insecure-cookie / sensitive-data-in-url 等）
   该 cookie 或 URL query 仅承载 UI 偏好 / A-B 实验 ID / 语言代码 / 主题，
   绝不涉及鉴权、会话或 PII。证据必须是变量名本身，或注释 / JavaDoc 中明确说明用途。

---

## 🚫 禁用的 DEFENDED 理由（出现即翻转为 VULNERABLE）

只要 `defense_analysis` 中出现以下托词，**直接判定为 VULNERABLE**。
这些是反复观察到的 LLM 用来"洗白"真实漏洞的常见借口：

- "这是测试 / benchmark / demo / sample / example / lab / sonar 项目代码。"
  CWE 定义按代码**行为**判定，不看项目类别。生产仓库里也存在测试目录，
  且测试代码会在 CI 中执行。

- "包名 / 文件名 / 路径含 `test` / `benchmark` / `demo` / `sonar` / `report` / `fixture`。"
  路径名不是安全边界。真实问题是危险结构存在于编译产物中。

- "非生产凭据 / 仅本地开发 / 内部工具不上公网。"
  CWE-798 是按行定性的缺陷。凭据可能通过 git 历史、备份、屏幕共享外泄。
  使用范围不构成防御。

- "静态扫描器对此类模式经常误报。"
  你**就是**那个二次裁决器。这种托词等于把责任循环推给上游 —— 不解决任何问题。

- "值是硬编码所以不可被用户控制。"
  对于 fast-path 类 sink（CWE-327 弱加密、CWE-798 硬编码凭据等），
  问题不在"是否可控"而在"危险结构本身"。
