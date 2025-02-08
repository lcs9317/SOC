# DDoS Detection System

이 프로젝트는 다양한 오픈소스 도구(TensorFlow, Kafka, Elasticsearch, Kibana, Logstash, Zeek, Nginx 등)를 활용하여 DDoS 공격을 탐지하기 위한 AI 기반 솔루션입니다.  
네트워크 트래픽을 Zeek가 캡처하여 Kafka로 전송하고, 이를 Logstash가 Elasticsearch에 저장합니다. 또한, AI 모델을 통해 실시간으로 트래픽의 이상 여부를 판단하여 Elasticsearch에 인덱싱하며, Kibana와 Nginx를 통해 시각화 및 외부 접근이 가능합니다.

---

## 목차

- [구성 요소 개요](#구성-요소-개요)
- [폴더 구조](#폴더-구조)
- [사전 요구사항](#사전-요구사항)
- [설치 및 실행](#설치-및-실행)
  - [1. Repository 클론](#1-repository-클론)
  - [2. 데이터셋 준비](#2-데이터셋-준비)
  - [3. Docker Compose 빌드 및 실행](#3-docker-compose-빌드-및-실행)
  - [4. AI 모델 학습](#4-ai-모델-학습)
  - [5. AI 모델 추론](#5-ai-모델-추론)
  - [6. 결과 확인 (Kibana & Nginx)](#6-결과-확인-kibana--nginx)
- [세부 구성 요소 설명](#세부-구성-요소-설명)
  - [AI Model Trainer (./trainer)](#ai-model-trainer-trainer)
  - [AI Model Inference (./inference)](#ai-model-inference-inference)
  - [Zeek (./zeek)](#zeek-zeek)
  - [Logstash (./logstash)](#logstash-logstash)
  - [Elasticsearch & Kibana](#elasticsearch--kibana)
  - [Nginx & Certbot (./nginx)](#nginx--certbot-nginx)
- [환경 변수 설정](#환경-변수-설정)
- [문제 해결 및 참고 사항](#문제-해결-및-참고-사항)
- [라이선스 및 기여](#라이선스-및-기여)

---

## 구성 요소 개요

이 프로젝트는 다음과 같은 여러 서비스로 구성되어 있습니다.

- **Zookeeper & Kafka**  
  Kafka 메시징 백본으로, 네트워크 트래픽 데이터(특징)를 처리합니다.

- **Zeek**  
  네트워크 트래픽을 캡처하고, 트래픽의 다양한 피처(feature)를 추출하여 Kafka의 `network-traffic` 토픽으로 전송합니다.  
  Zeek 스크립트(`InferenceKafka.zeek`, `local.zeek`)를 통해 Kafka 연동을 구성합니다.

- **Logstash**  
  Kafka의 `network-traffic` 토픽에서 데이터를 수신하여 Elasticsearch의 `network-traffic` 인덱스로 전달합니다.

- **Elasticsearch & Kibana**  
  Elasticsearch는 로그 및 인덱싱 데이터를 저장하며, Kibana는 이를 시각화합니다.

- **AI Model Trainer**  
  `trainer` 디렉터리 내의 코드를 이용해 DDoS 탐지 모델(LSTM 또는 CNN)을 학습시킵니다.  
  학습 결과(모델 파일과 스케일러)는 `models` 디렉터리에 저장됩니다.

- **AI Model Inference**  
  `inference` 디렉터리의 코드는 Kafka에서 네트워크 트래픽 데이터를 읽어 학습된 모델로 추론을 수행합니다.  
  추론 결과(예측 결과)는 Elasticsearch의 `ddos-detection` 인덱스로 저장됩니다.

- **Nginx & Certbot**  
  Nginx는 리버스 프록시로 Kibana에 접근할 수 있도록 하며, Certbot을 통해 Let's Encrypt 인증서를 관리합니다.

- **Docker Compose**  
  `docker-compose.yml` 파일을 통해 위의 모든 서비스를 컨테이너화하여 손쉽게 구축 및 실행할 수 있습니다.

---

## 폴더 구조

.
├── docker-compose.yml
├── datasets/                  # DDoS 학습 데이터셋 (CSV 파일: DDoS2019.csv)
├── models/                    # 학습 완료 후 저장되는 모델 및 스케일러 파일
├── inference/
│   ├── Dockerfile             # AI 추론 서비스 도커파일
│   ├── inference.py           # Kafka 메시지 소비 및 모델 추론 코드
│   └── requirements.txt       # Python 의존성 목록
├── logstash/
│   └── pipeline               # Logstash 파이프라인 설정 (Kafka → Elasticsearch)
├── nginx/
│   ├── conf.d/
│   │   └── default.conf       # Nginx 리버스 프록시 설정 (Kibana 프록시)
│   └── html/
│       └── index.html         # 기본 정적 페이지 (ACME 챌린지용)
├── trainer/
│   ├── Dockerfile             # AI 모델 학습 서비스 도커파일
│   ├── trainer.py             # 모델 학습 및 평가 코드 (LSTM/CNN 지원)
│   └── requirements.txt       # Python 의존성 목록
└── zeek/
    ├── Dockerfile             # Zeek 및 zeek-kafka 플러그인 설치 도커파일
    ├── zeek.cfg               # Zeek 설정 파일
    ├── scripts/
    │   └── InferenceKafka.zeek  # Zeek 스크립트 (Kafka 전송용)
    └── local.zeek             # Zeek 로컬 설정 (Kafka, 로그 파일 등)






---

## 사전 요구사항

- **Docker** 및 **Docker Compose**
- 학습에 사용할 **CSV 데이터셋 (DDoS2019.csv)** 파일을 `datasets/` 디렉터리에 준비할 것
- 필요한 포트(2181, 9092, 29092, 9200, 5601, 8080, 443 등)가 사용 가능해야 함

---

## 설치 및 실행

### 1. Repository 클론

```bash
git clone <repository_url>
cd <repository_directory>


### 2. 데이터셋 준비

- `datasets/` 디렉터리에 **DDoS2019.csv** 파일을 복사합니다.

### 3. Docker Compose 빌드 및 실행

모든 서비스를 빌드하고 실행하려면 아래 명령어를 사용합니다.

```bash
docker-compose up -d
이 명령은 다음 서비스를 실행합니다.

- **Zookeeper & Kafka**
- **Zeek**
- **Logstash**
- **Elasticsearch & Kibana**
- **Nginx & Certbot**
- **AI Model Inference**  
  *(모델 파일은 `models/` 디렉터리에 있어야 올바르게 작동합니다.)*

> **참고**: Zeek 컨테이너는 `host` 네트워크 모드를 사용하므로 실제 네트워크 인터페이스에 접근합니다.  
> 네트워크 설정이 환경에 맞게 구성되어 있는지 확인하세요.

---

## 4. AI 모델 학습

학습은 `trainer` 서비스(일회성 실행)에서 진행합니다.

```bash
docker-compose run trainer

- 기본적으로 LSTM 모델을 학습하며, `models/ddos_model.h5`와 `models/scaler.pkl` 파일이 생성됩니다.
- CNN 모델로 학습하려면 다음과 같이 실행합니다:

  ```bash
  docker-compose run trainer cnn

  학습이 완료되면 `models/` 디렉터리에 결과 파일이 저장되었는지 확인합니다.

### 5. AI 모델 추론

`ai-inference` 서비스는 Kafka로부터 네트워크 트래픽 데이터를 읽어 학습된 모델로 추론을 수행합니다.

- 기본적으로 LSTM 모델을 사용하며, `MODEL_TYPE` 환경변수를 `cnn`으로 설정하면 CNN 모델을 사용합니다.
- 컨테이너 로그를 통해 추론 및 Elasticsearch 인덱싱 결과를 확인할 수 있습니다.

```bash
docker logs ai-inference

### 6. 결과 확인 (Kibana & Nginx)

- **Kibana:**  
  브라우저에서 [http://localhost:5601](http://localhost:5601)에 접속하여 Elasticsearch에 저장된 데이터를 확인할 수 있습니다.

- **Nginx Reverse Proxy:**  
  Nginx는 8080 포트(HTTP)와 443 포트(HTTPS)를 리버스 프록시로 사용하여 Kibana에 접근할 수 있도록 설정되어 있습니다.  
  예: [https://lcs9317.ddns.net](https://lcs9317.ddns.net)
