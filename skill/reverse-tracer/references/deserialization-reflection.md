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

## 常见误判

- ❌ "代码里有 try/catch 包了 ClassNotFoundException" —— 不是过滤，gadget 类一般是已存在的常用库类
- ❌ "用了 XStream 就是安全的" —— XStream **默认不安全**，必须看到 `addPermission` 才算
- ❌ "数据来自数据库不是 HTTP" —— 数据库内容仍可能被先前的 SQL Injection 写入
- ❌ "教学项目" 借口
