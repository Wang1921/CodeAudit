# XXE (XML External Entity, CWE-611)

## sink 模式速查

按 XML 解析器类型分三家族：

### DOM 解析
- `DocumentBuilder.parse($INPUT, ...)` —— JAXP DOM
- `new SAXReader().read($INPUT)` —— dom4j
- `new SAXBuilder().build($INPUT)` —— jdom2

### SAX / Stream 解析
- `SAXParser.parse($INPUT, $HANDLER)` —— JAXP SAX
- `XMLReader.parse($SOURCE)` —— `org.xml.sax.XMLReader`
- `XMLInputFactory.createXMLStreamReader($INPUT)` —— StAX 流式
- `XMLInputFactory.createXMLEventReader($INPUT)` —— StAX 事件

### XSLT / Schema / Validate / JAXB
- `TransformerFactory.newTransformer($SRC)` —— XSLT
- `SchemaFactory.newSchema($SRC)` —— XSD 校验
- `Validator.validate($SRC)` —— XSD 校验
- `XPath.evaluate($EXPR, $XML_SRC, ...)` —— XPath 用 XML Source
- `Unmarshaller.unmarshal($INPUT)` —— JAXB

## 数据流追溯重点

1. 找 XML 解析 sink；
2. 看输入来源：
   - `@RequestBody String xml` / `request.getInputStream()` / `multipartFile.getInputStream()`
   - 文件读取（如先上传后解析，仍可能用户控制）
3. 输入可控 + 未禁用 DTD/外部实体 → VULNERABLE。

## 常见误判

- ❌ "项目里有 setFeature 调用" —— 看是不是**对当前 sink 用的 factory**设置的，不能跨 factory
- ❌ "Java 8u121+ 默认禁用" —— **不是默认**，要看 JVM 启动参数 `-Djdk.xml.entityExpansionLimit=0` 等
- ❌ "数据是本地文件不是 HTTP" —— 文件内容仍可能被上一步攻击者写入
- ❌ "教学项目"借口
