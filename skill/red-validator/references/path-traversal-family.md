# Path Traversal Family（Path Traversal / Zip Slip / Insecure Temp File）

## 误判案例

| 防御手段 | 误判场景 | 为什么安全 |
|---|---|---|
| Path.normalize() + startsWith(baseDir) | `Path.resolve(userInput).normalize().startsWith(baseDir)` | `../` 被 normalize 折叠，路径无法逃出 baseDir |
| 白名单文件名 | `if (!ALLOWED_FILES.contains(filename)) throw ...` | 只允许预定义文件名，`../` 序列无法通过 |
| UUID 文件名 | 服务端生成 UUID 作为存储文件名，原始文件名不参与路径构造 | 外部输入不影响文件系统路径 |
| 只读权限 | 目标目录挂载为只读 | 即使路径逃逸也无法写入 |
| java.nio.File.open() 带 OPEN_READ | 仅打开读取通道，无写权限 | 写入型攻击不可行 |

## 绕过案例

| 看似防御 | 绕过思路 | 示例 |
|---|---|---|
| 只检查 `..` 字符串 | URL 编码 / 双编码绕过 | `..%2f` / `..%252f` — 服务端解码后恢复 `../` |
| `startsWith(baseDir)` 无 normalize | 不折叠 `./` / `../` | `/var/data/../../etc/passwd` — startswith 通过但实际逃逸 |
| `startsWith(baseDir)` 用字符串匹配 | 路径注入 | `/var/dataevil/` — baseDir `/var/data` 匹配但不是预期目录 |
| null 字节截断（旧版 JDK < 7u40） | `%00` 截断后缀 | `../../../etc/passwd%00.jpg` — 文件系统读到 `/etc/passwd` |
| Windows 路径分隔符 | `..\` 在 Linux 被当文件名，Windows 可逃逸 | `..\..\Windows\System32\config\SAM` |
| Zip Slip：解压时不校验 entry name | ZIP 内含 `../../../../var/www/html/shell.jsp` | 解压时写入 webroot |
| 符号链接 | 攻击者预建 `link -> /etc` | `new File(baseDir, "link/passwd")` — 通过 symlink 逃逸 |
| 仅校验文件后缀 | 路径穿越不依赖后缀 | `../../../etc/passwd.pdf` — 后缀合法但路径逃逸 |
| File.getCanonicalPath() 比对但异常吞掉 | catch 里继续执行 | `try { canonical check } catch { /* continue */ }` — 校验失败仍执行 |
