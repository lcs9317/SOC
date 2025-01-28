# Kafka Elasticsearch Setup

## 개요
이 프로젝트는 Kafka와 Elasticsearch를 연동하는 환경을 Docker Compose를 사용하여 구성합니다.

## 구성 요소
- Apache Kafka
- Zookeeper
- Kafka Connect
- Elasticsearch

## 실행 방법
1. Docker와 Docker Compose가 설치되어 있어야 합니다.
2. 프로젝트 루트 디렉토리에서 다음 명령어를 실행합니다:


## 데이터 수집 및 전처리
- 현재는 **network-collector(Scapy)**를 통해 네트워크 트래픽을 캡처한 뒤 **Kafka**에 적재하고,
  **Kafka Connect**를 통해 Elasticsearch로 전송하고 있음.
- 추후 고급 전처리나 추가 파이프라인이 필요하면 **Logstash** 혹은 **Fluentd**를 도입하여
  Kafka 토픽 데이터를 필터링/변환 후 Elasticsearch나 Splunk 등 SIEM으로도 연동할 계획.
