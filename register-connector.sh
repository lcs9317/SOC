#!/bin/bash

# Kafka 준비 상태 확인
echo "Waiting for Kafka broker to be ready..."
until nc -z kafka 29092; do
  sleep 5
  echo "Kafka broker is not ready yet..."
done

echo "Kafka broker is ready. Proceeding..."

# (옵션) Python 스크립트로 ddos-detection에 메시지 전송 -> auto.create.topics.enable=true 이면 자동 생성됨
python3 /usr/local/bin/producer.py || echo "Failed to send test message."

# Kafka Connect 설정 등록
curl -X POST -H "Content-Type: application/json" \
  --data @/tmp/connect-elasticsearch-sink.json \
  http://kafka-connect:8083/connectors || echo "Failed to register elasticsearch connector."

curl -X POST -H "Content-Type: application/json" \
  --data @/tmp/network_traffic_sink.json \
  http://kafka-connect:8083/connectors || echo "Failed to register network traffic connector."

exec /etc/confluent/docker/run
