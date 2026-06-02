# XXE (XML External Entity, CWE-611)

## 防御机制速查（每种解析器有专属配置）

### JAXP（DOM/SAX）
```java
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setXIncludeAware(false);                            // DocumentBuilderFactory 才有
factory.setExpandEntityReferences(false);                   // 同上
```

### StAX (XMLInputFactory)
```java
xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
xif.setProperty("javax.xml.stream.isSupportingExternalEntities", false);
```

### TransformerFactory / SchemaFactory
```java
tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
sf.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
sf.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
```

### dom4j SAXReader / jdom2 SAXBuilder
```java
reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
```

### JAXB Unmarshaller
不要直接 `unmarshal(InputStream)`；改用 `SAXSource` 包装已安全配置的 XMLReader：
```java
XMLReader reader = saxParserFactory.newSAXParser().getXMLReader();
reader.setFeature(...);  // 上面所有 feature
SAXSource source = new SAXSource(reader, new InputSource(input));
unmarshaller.unmarshal(source);
```

## 常见误判

- ❌ "项目里有 setFeature 调用" —— 看是不是**对当前 sink 用的 factory**设置的，不能跨 factory
- ❌ "Java 8u121+ 默认禁用" —— **不是默认**，要看 JVM 启动参数 `-Djdk.xml.entityExpansionLimit=0` 等
- ❌ "数据是本地文件不是 HTTP" —— 文件内容仍可能被上一步攻击者写入
- ❌ "教学项目"借口

## 证据引用范例

**DEFENDED 时**：
```
defense_analysis: "Line 18 DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                  Line 19 factory.setFeature(
                    \"http://apache.org/xml/features/disallow-doctype-decl\", true);
                  Line 20 factory.setXIncludeAware(false);
                  — 在 factory.newDocumentBuilder() 之前完整禁用 DTD 解析和 XInclude,
                  攻击者无法注入 <!ENTITY xxe SYSTEM ...>."
```

**VULNERABLE 时**：
```
suspicion_reason: "Line 82 var unmarshaller = jc.createUnmarshaller();
                  Line 82 return (Comment) unmarshaller.unmarshal(xsr);
                  — xsr (XMLStreamReader) 由 line 79 xif.createXMLStreamReader 创建,
                  且 securityEnabled=false 分支未对 xif 设置 SUPPORT_DTD=false,
                  导致 JAXB 解析时仍允许外部实体引用."
```
