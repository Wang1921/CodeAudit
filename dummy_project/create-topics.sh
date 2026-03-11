#!/bin/bash

# Kafka Topics 创建脚本

echo "等待 Kafka 启动..."
sleep 10

KAFKA_HOST="localhost:9092"

echo "创建 Topics..."

# 创建 eval-requests topic
docker exec -kafka kafka kafka-topics --create \
  --if-not-exists \
  --bootstrap-server $KAFKA_HOST \
  --replication-factor 1 \
  --partitions 1 \
  --topic eval-requests

# 创建 eval-replies topic
docker exec -kafka kafka kafka-topics --create \
  --if-not-exists \
  --bootstrap-server $KAFKA_HOST \
  --replication-factor 1 \
  --partitions 1 \
  --topic eval-replies

# 创建 ping-requests topic
docker exec -kafka kafka kafka-topics --create \
  --if-not-exists \
  --bootstrap-server $KAFKA_HOST \
  --replication-factor 1 \
  --partitions 1 \
  --topic ping-requests

# 创建 ping-replies topic
docker exec -kafka kafka kafka-topics --create \
  --if-not-exists \
  --bootstrap-server $KAFKA_HOST \
  --replication-factor 1 \
  --partitions 1 \
  --topic ping-replies

echo "Topics 创建完成！"

# 列出所有 topics
echo "当前 Topics："
docker exec -kafka kafka kafka-topics --list --bootstrap-server $KAFKA_HOST
