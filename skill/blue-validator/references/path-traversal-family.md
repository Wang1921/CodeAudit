# Path Traversal Family（Path Traversal / Zip Slip / Insecure Temp File）

## 共性

文件路径接收外部输入时，`../` 序列让攻击者跳出预期目录，读写任意文件。
**写入**场景比读取更严重（可能覆盖 webshell / 配置 → RCE）。

## 防御机制速查

### 规范化 + 前缀校验（最稳）
```java
Path base = Paths.get("/safe/dir").toAbsolutePath().normalize();
Path target = base.resolve(userInput).normalize();
if (!target.startsWith(base)) throw new SecurityException();
Files.readAllBytes(target);
```

### 白名单文件名（更稳）
```java
if (!Pattern.matches("[a-zA-Z0-9._-]+", userInput)) throw ...;
```
（拒绝 `/`, `\`, `..`, `:`, 空字节 `\0`）

### URL 解码再检查
```java
String decoded = URLDecoder.decode(userInput, UTF_8);
if (decoded.contains("..") || decoded.contains("/")) throw ...;
// ⚠️ 但二次编码仍可绕过单次解码
```

### 文件名哈希
```java
String safeFilename = DigestUtils.sha256Hex(content);  // 用文件内容 hash 做文件名
```

### Zip Slip 专属
```java
ZipEntry entry = ...;
File targetFile = new File(baseDir, entry.getName());
String basePath = baseDir.getCanonicalPath();
String targetPath = targetFile.getCanonicalPath();
if (!targetPath.startsWith(basePath + File.separator)) throw new ZipSlipException();
```

## 常见误判

- ❌ "代码检查了 `..` 字符串" —— 二次编码（`%252e%252e`）/ 反斜杠（Windows）/ 空字节注入可绕过
- ❌ "用了 `Paths.get` 就安全" —— 关键看后续是否 normalize + startsWith 校验
- ❌ "上传到固定 basedir 就安全" —— `new File(basedir, "../../etc/passwd")` 仍会跳出
- ❌ "Spring Resource 类名看起来安全" —— ClassPathResource / FileSystemResource 同样接收任意路径
- ❌ "教学项目"借口

## 证据引用范例

**DEFENDED 时**：
```
defense_analysis: "Line 45 Path base = Paths.get(uploadDir).toAbsolutePath().normalize();
                  Line 46 Path target = base.resolve(filename).normalize();
                  Line 47 if (!target.startsWith(base)) throw new SecurityException();
                  — 标准 OWASP 模板,前缀校验拦截所有 ../ 跳出尝试."
```

**VULNERABLE 时**：
```
suspicion_reason: "Line 51 File targetFile = new File(uploadDir, fullName);
                  — fullName 来自 @RequestParam (line 38),未经任何路径校验直接拼接,
                  攻击者输入 '../../../etc/passwd' 即可读任意文件."
```
