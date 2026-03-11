# 多微服务测试项目（Kafka 通信）

## 📋 项目概述

这是一个用于测试 CodeAudit 系统跨服务漏洞追踪能力的多微服务架构项目。

## 🏗️ 架构

```
user-service (8080)     →  Kafka Topics  →  processor-service (8081)
     /api/eval              eval-requests                SpEL Injection
     /api/ping               ping-requests                Command Injection
```

## 🚀 快速开始

### 1. 启动 Kafka

```bash
cd dummy
_project
docker-compose up -d
```

等待 Kafka 启动（约 10 秒），然后创建 Topics：

```bash
./create-topics.sh
```

### 2. 启动微服务

**启动 user-service**（端口 8080）：
```bash
cd user-service
mvn spring-boot:run
```

**启动 processor-service**（端口 8081）：
```bash
cd processor-service
mvn spring-boot:run
```

### 3. 测试接口

**测试 SpEL 注入**：
```bash
# 正常请求
curl -X POST "http://localhost:8080/api/eval?expression=hello"

# 漏洞攻击（SpEL 注入）
curl -X POST "http://localhost:8080/api/eval?expression=T(java.lang.Runtime).getRuntime().exec('whoami')"
```

**测试命令注入**：
```bash
# 正常请求
curl -X POST "http://localhost:8080/api/ping?target=127.0.0.1"

# 漏洞攻击（命令注入）
和其他
curl -X POST "http://localhost:8080/api/ping?target=127.0.0.1;whoami"
```

## 🎯 漏洞特征

### processor-service 中的漏洞

1. **SpEL 表达式注入** (CWE-917)
   - 文件：`processor-service服务/impl/EvalServiceImpl.java`
   - 代码：`parser.parseExpression(expression).getValue(String.class)`
   - 攻击链路：user-service → Kafka → processor-service → SpEL

2. **命令注入** (CWE-78)
   - 文件：`processor-service/src/main/java/com/example/processor/service/impl/PingServiceImpl.java`
   - 代码：`Runtime.getRuntime().exec(cmd)`
   - 攻击链路：user-service → Kafka → processor-service → exec()

## 📡 Kafka Topics

| Topic | 用途 |
|-------|------|
| `eval-requests` | SpEL 评估请求 |
| `eval-replies` | SpEL 评估响应 |
| `ping-requests` | Ping 请求 |
| `ping-replies` | Ping 响应 |

## 🔧 运行 CodeAudit

```bash
# 从项目根目录运行
cd /home/CodeAudit
python -m src.main ./dummy_project
```

CodeAudit 系统应该能够：
1. 识别两个微服务
2. 提取 API 路由
3. 检测到 processor-service 中的漏洞
4. 追踪 Kafka 消息流
5. 生成跨服务攻击链路

## 🛑 停止服务

```bash
# 停止 Kafka
docker-compose down

# 停止微服务（Ctrl+C）
```

## 📝 注意事项

⚠️ **此项目仅用于测试 CodeAudit 系统的跨服务漏洞追踪能力，包含真实的安全漏洞代码，严禁在生产环境使用！**
