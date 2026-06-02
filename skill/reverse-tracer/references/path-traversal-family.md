# Path Traversal Family（Path Traversal / Zip Slip / Insecure Temp File）

## 共性

文件路径接收外部输入时，`../` 序列让攻击者跳出预期目录，读写任意文件。
**写入**场景比读取更严重（可能覆盖 webshell / 配置 → RCE）。

## sink 模式速查

### 通用 File API
- `new File($PATH)` / `new File($PARENT, $PATH)`
- `Paths.get($PATH, ...)` / `Path.of($PATH, ...)` (Java 11+)
- `new FileInputStream/FileOutputStream/FileReader/FileWriter($PATH)`
- `new RandomAccessFile($PATH, ...)`
- `Files.readAllBytes/readString/newInputStream/newOutputStream/write/copy($PATH, ...)`
- `FileChannel.open($PATH, ...)`
- `Class/ClassLoader.getResourceAsStream($PATH)`

### Spring Resource 封装
- `new ClassPathResource/FileSystemResource/UrlResource/PathResource/InputStreamResource($PATH)`
- `ResourceUtils.getFile($PATH)` / `getURL($PATH)`
- `MultipartFile.transferTo($PATH)` —— 文件上传转存

### Apache Commons IO
- `FileUtils.readFileToString/writeStringToFile/copyFile/copyDirectory/deleteDirectory/forceDelete($PATH, ...)`

### Guava
- `com.google.common.io.Files.asByteSource/asCharSource/readLines($PATH)`

### 远程文件系统
- JSch SFTP: `$SFTP.get($PATH)` / `put($SRC, $PATH)` / `ls/cd/rm($PATH)`
- Apache VFS: `$FS.resolveFile($PATH)`
- Hadoop HDFS: `new Path($PATH)` / `new org.apache.hadoop.fs.Path($PATH)`

### Zip Slip 专属
- `new ZipInputStream(...)` + `ZipEntry.getName()` 用作文件路径
- Apache Compress / zip4j 同类操作

### Insecure Temp File 专属
- `File.createTempFile($PREFIX, $SUFFIX, $DIR)` —— $PREFIX/$DIR 含用户输入
- `Files.createTempDirectory($PREFIX)` / `createTempFile($PREFIX, ...)`

## 数据流追溯重点

1. 找 sink 的"路径字符串参数"；
2. 看来源：
   - `@RequestParam String filename` / `@PathVariable` / `@RequestBody`
   - `MultipartFile.getOriginalFilename()` ⚠️ **极常见 sink**
   - `request.getHeader("X-File-Name")`
   - `ZipEntry.getName()` ⚠️ **Zip Slip 核心**
   - 数据库存储的文件名（间接污染）
3. 任一可控 + 无路径校验 → VULNERABLE。

## 常见误判

- ❌ "代码检查了 `..` 字符串" —— 二次编码（`%252e%252e`）/ 反斜杠（Windows）/ 空字节注入可绕过
- ❌ "用了 `Paths.get` 就安全" —— 关键看后续是否 normalize + startsWith 校验
- ❌ "上传到固定 basedir 就安全" —— `new File(basedir, "../../etc/passwd")` 仍会跳出
- ❌ "Spring Resource 类名看起来安全" —— ClassPathResource / FileSystemResource 同样接收任意路径
- ❌ "教学项目"借口
