# Deserialization & Reflection Family（Unsafe Deserialization / Unsafe Reflection）

## 误判案例

| 防御手段 | 误判场景 | 为什么安全 |
|---|---|---|
| Java Serial Klobber / look-ahead | `ObjectInputStream` 子类 `resolveClass()` 白名单 | 只允许预定义类，gadget chain 的类无法加载 |
| Kryo 白名单注册 | `kryo.setRegistrationRequired(true)` | 未注册的类直接抛异常 |
| Jackson `@JsonTypeInfo(use=Id.NAME)` | 用逻辑类型名而非 Java 类名 | `@type` 只能是预注册的别名，无法指定任意类 |
| XStream 安全框架 | `xstream.allowTypes(new Class[]{Safe.class})` | 未允许的类无法反序列化 |
| Fastjson AutoType 关闭 | `ParserConfig.getGlobalInstance().setAutoTypeSupport(false)` | `@type` 不触发类加载 |
| ObjectInputFilter (JDK 9+) | `ObjectInputFilter.Config.createFilter("com.safe.*;!*")` | JDK 级别白名单过滤 |
| 白名单反序列化 | `allowedTypes.contains(className)` | 只允许安全类通过 |

## 绕过案例

| 看似防御 | 绕过思路 | 示例 |
|---|---|---|
| Fastjson AutoType 关闭但用 1.2.48 以下版本 | 缓存投毒绕过 | `{"@type":"java.lang.Class","val":"com.evil.Gadget"}` — 先将恶意类加入缓存，再用 `@type` 实例化 |
| Fastjson autoTypeSupport=true | Lombok 缓存绕过 | `{"@type":"com.evil.Gadget"}` — 开启 autoType 后任意类可加载 |
| XStream 默认配置（1.4.x 之前） | 无安全框架 | 任意类可直接反序列化 |
| Jackson `DefaultTyping.NON_FINAL` | 接口/抽象类仍可被指定 | `["com.evil.Gadget", {...}]` — 只需目标类非 final |
| ObjectInputStream 白名单遗漏 | gadget chain 使用不在黑名单的类 | CommonsBeanutils1 用 `BeanComparator` 不依赖 CommonsCollections |
| 只过滤 `ysoserial` 已知 gadget | 新 gadget chain | 使用不依赖 Apache Commons 的链（JDK 原生链如 `HashMap + URL` 触发 DNS） |
| Serial Filter 黑名单 | 黑名单不完整 | JDK 更新添加新黑名单，旧版本不包含新发现的 gadget |
| Kryo `registrationRequired=false` | 任意类可注册 | 未设置时 Kryo 允许未知类反序列化 |
| SnakeYAML 无 SafeConstructor | `!!` 前缀可实例化任意类 | `!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [...]]` |
| Unsafe Reflection 过滤 `Runtime` | 反射链不直接用 Runtime | `Class.forName("java.lang.ProcessBuilder").getConstructor(List.class).newInstance(cmds)` |
| 白名单匹配用 `startsWith` | 包名前缀匹配被绕过 | 白名单 `com.safe.` 但 `com.safe.evil.Gadget` 可通过 |
