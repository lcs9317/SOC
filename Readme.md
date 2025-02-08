# Distributed DDoS Detection System Manual / 분산 DDoS 탐지 시스템 매뉴얼

이 문서는 Distributed DDoS Detection System의 매뉴얼을 영어와 한국어 두 가지 버전으로 제공합니다.  
원하는 언어의 섹션을 참고하시기 바랍니다.

---

## English Version

### Table of Contents
1. [Overview](#overview)
2. [System Architecture](#system-architecture)
3. [Component Descriptions](#component-descriptions)
    - [AI Inference](#ai-inference)
    - [AI Trainer](#ai-trainer)
    - [Logstash Pipeline](#logstash-pipeline)
    - [Nginx Reverse Proxy & Certbot](#nginx-reverse-proxy--certbot)
    - [Zeek Network Monitoring](#zeek-network-monitoring)
    - [Core Services: Kafka, Zookeeper, Elasticsearch & Kibana](#core-services-kafka-zookeeper-elasticsearch--kibana)
4. [Installation and Setup](#installation-and-setup)
5. [Execution Guide](#execution-guide)
6. [Networking and Volumes](#networking-and-volumes)
7. [Notes and Recommendations](#notes-and-recommendations)

### Overview

The Distributed DDoS Detection System is designed to monitor network traffic, ingest data via Kafka, process logs with Logstash and Elasticsearch, visualize data through Kibana, and detect DDoS attacks using AI inference. It comprises multiple Docker containers orchestrated via Docker Compose.

### System Architecture

The system includes:
- **AI Inference**: Consumes data from Kafka, performs inference with a pre-trained model (LSTM/CNN), and indexes results in Elasticsearch.
- **AI Trainer**: Trains a DDoS detection model using CSV data (e.g., CIC-DDoS2019) and saves the model and scaler.
- **Logstash Pipeline**: Transfers data from Kafka to Elasticsearch.
- **Nginx Reverse Proxy & Certbot**: Provides secure HTTPS access to Kibana using Let's Encrypt certificates.
- **Zeek Network Monitoring**: Captures network flows and sends logs to Kafka.
- **Core Services**: Kafka, Zookeeper, Elasticsearch, and Kibana.

### Component Descriptions

#### AI Inference
- **Location**: `inference/`
- **Key Files**:
    - **Dockerfile**  
      Sets up a TensorFlow-based container, installs dependencies, and runs the `inference.py` script.
    - **inference.py**  
      Reads network traffic data from Kafka, preprocesses it, performs inference using a trained model, and indexes results in Elasticsearch.
    - **requirements.txt**  
      Lists required Python packages such as `confluent_kafka`, `elasticsearch`, `scikit-learn`, `pandas`, and `joblib`.

#### AI Trainer
- **Location**: `trainer/`
- **Key Files**:
    - **Dockerfile**  
      Sets up a TensorFlow CPU-based container for training.
    - **trainer.py**  
      Loads CSV data (e.g., CIC-DDoS2019), preprocesses it, trains a DDoS detection model (LSTM/CNN), evaluates performance, and saves the model and scaler in `/app/models`.
    - **requirements.txt**  
      Contains required Python packages such as `pandas`, `numpy`, `scikit-learn`, and `joblib`.

#### Logstash Pipeline
- **Location**: `logstash/`
- **Key Files**:
    - **pipeline**  
      Configures Logstash to read messages from the Kafka topic "network-traffic" and forward them to Elasticsearch.

#### Nginx Reverse Proxy & Certbot
- **Location**: `nginx/`
- **Key Files**:
    - **conf.d/default.conf**  
      Configures Nginx to serve ACME challenge files for Let's Encrypt and proxy all non-ACME requests to Kibana.
    - **html/index.html**  
      Provides a default web page.
- **Certbot**:  
  Runs as a separate container (defined in `docker-compose.yml`) to automatically renew Let's Encrypt certificates.

#### Zeek Network Monitoring
- **Location**: `zeek/`
- **Key Files**:
    - **Dockerfile**  
      Sets up an Ubuntu 22.04-based container that installs Zeek, build tools, `librdkafka`, and the `zeek-kafka` plugin. Host networking is used for real-time traffic capture.
    - **zeek.cfg**  
      Configures Zeek to load necessary scripts such as `zeek-kafka`, `InferenceKafka.zeek`, and local configuration.
    - **scripts/InferenceKafka.zeek**  
      A Zeek script module that processes network flow data and sends it to Kafka.
    - **local.zeek**  
      Contains local settings for Zeek (e.g., log directory path, Kafka configuration).

#### Core Services: Kafka, Zookeeper, Elasticsearch & Kibana
- **Managed via**: `docker-compose.yml`
- **Services**:
    - **Zookeeper**: Coordinates Kafka brokers.
    - **Kafka**: Handles messaging and data ingestion.
    - **Elasticsearch**: Indexes and stores data for analytics.
    - **Kibana**: Provides a user interface for data visualization.

### Installation and Setup

#### Prerequisites
- Docker and Docker Compose must be installed.
- Create the following directories on your host for data persistence:
    - `datasets` — For training data (e.g., CIC-DDoS2019 CSV file)
    - `models` — For storing trained models and scalers
    - `zeek/logs` — For Zeek log storage
    - `nginx/conf.d` — For Nginx configuration files
    - `nginx/html` — For Nginx web content

#### Repository Setup
1. Clone the repository:
    ```bash
    git clone <repository-url>
    cd <repository-directory>
    ```
2. Modify `docker-compose.yml` as needed (e.g., domain names, port settings).

### Execution Guide

1. **Build and run all containers:**
    ```bash
    docker-compose up --build
    ```
2. **(Optional) Train the AI model:**
    Ensure your dataset is in the `datasets` directory, then run:
    ```bash
    docker-compose run trainer
    ```
3. **Access Kibana:**
    - HTTP: [http://lcs9317.ddns.net:8080](http://lcs9317.ddns.net:8080)
    - HTTPS: [https://lcs9317.ddns.net](https://lcs9317.ddns.net)

### Networking and Volumes

- **Networking**:  
  All services communicate over the `kafka_network` Docker bridge network.
- **Volumes**:
    - `zeek/logs`: Persists Zeek log data.
    - `models`: Shared between Trainer and Inference for storing models and scalers.
    - `datasets`: Contains training datasets.
    - `nginx` directories: Store Nginx configuration, web content, and certificates.

### Notes and Recommendations

- **Network Settings**: Ensure your host network allows container-to-container communication.
- **Domain Setup**: Verify that your domain (e.g., `lcs9317.ddns.net`) is correctly configured.
- **Resource Allocation**: Adjust memory and CPU limits in `docker-compose.yml` based on your system capacity.
- **Security Considerations**: Enhance security settings for Kafka, Elasticsearch, Kibana, and other components in production.
- **Monitoring**: Regularly review logs and performance metrics to ensure stable operation.

---

## Korean Version

### 목차
1. [개요](#개요-1)
2. [시스템 아키텍처](#시스템-아키텍처-1)
3. [구성 요소 설명](#구성-요소-설명)
    - [AI 추론](#ai-추론)
    - [AI 학습](#ai-학습)
    - [Logstash 파이프라인](#logstash-파이프라인)
    - [Nginx 리버스 프록시 및 Certbot](#nginx-리버스-프록시-및-certbot)
    - [Zeek 네트워크 모니터링](#zeek-네트워크-모니터링)
    - [핵심 서비스: Kafka, Zookeeper, Elasticsearch & Kibana](#핵심-서비스-kafka-zookeeper-elasticsearch--kibana)
4. [설치 및 설정](#설치-및-설정)
5. [실행 가이드](#실행-가이드)
6. [네트워킹 및 볼륨 구성](#네트워킹-및-볼륨-구성)
7. [주의사항 및 권장사항](#주의사항-및-권장사항)

### 개요

분산 DDoS 탐지 시스템은 네트워크 트래픽을 모니터링하고, Kafka를 통해 데이터를 수집하며,  
Logstash와 Elasticsearch를 사용해 로그를 처리하고, Kibana를 통해 데이터를 시각화하며,  
AI 추론을 통해 DDoS 공격을 탐지하는 시스템입니다. 이 시스템은 Docker Compose로 오케스트레이션되는  
여러 Docker 컨테이너로 구성되어 있습니다.

### 시스템 아키텍처

시스템은 다음과 같은 구성 요소로 이루어져 있습니다:
- **AI 추론**: Kafka에서 데이터를 받아 미리 학습된 모델(LSTM/CNN)로 추론하고, 결과를 Elasticsearch에 저장합니다.
- **AI 학습**: CSV 데이터를 이용해 DDoS 탐지 모델을 학습하고, 모델과 스케일러를 저장합니다.
- **Logstash 파이프라인**: Kafka에서 데이터를 받아 Elasticsearch로 전달합니다.
- **Nginx 리버스 프록시 및 Certbot**: Let's Encrypt 인증서를 사용하여 Kibana에 HTTPS로 안전하게 접근할 수 있도록 합니다.
- **Zeek 네트워크 모니터링**: 네트워크 플로우를 캡처하여 Kafka로 로그를 전송합니다.
- **핵심 서비스**: Kafka, Zookeeper, Elasticsearch, Kibana 등으로 구성됩니다.

### 구성 요소 설명

#### AI 추론
- **위치**: `inference/`
- **주요 파일**:
    - **Dockerfile**  
      TensorFlow 기반 컨테이너를 설정하며, 의존성을 설치하고 `inference.py` 스크립트를 실행합니다.
    - **inference.py**  
      Kafka에서 네트워크 트래픽 데이터를 읽어 전처리 후, 학습된 모델로 추론하고 그 결과를 Elasticsearch에 인덱싱합니다.
    - **requirements.txt**  
      `confluent_kafka`, `elasticsearch`, `scikit-learn`, `pandas`, `joblib` 등의 필요한 Python 패키지 목록을 포함합니다.

#### AI 학습
- **위치**: `trainer/`
- **주요 파일**:
    - **Dockerfile**  
      TensorFlow CPU 버전을 기반으로 학습 환경을 구성합니다.
    - **trainer.py**  
      CIC-DDoS2019 CSV 데이터를 로드 및 전처리하여 DDoS 탐지 모델(LSTM/CNN)을 학습 및 평가하고, 모델과 스케일러를 `/app/models`에 저장합니다.
    - **requirements.txt**  
      `pandas`, `numpy`, `scikit-learn`, `joblib` 등 필요한 Python 패키지 목록을 포함합니다.

#### Logstash 파이프라인
- **위치**: `logstash/`
- **주요 파일**:
    - **pipeline**  
      Kafka에서 "network-traffic" 토픽의 데이터를 읽어 Elasticsearch로 전송하는 Logstash 설정 파일입니다.

#### Nginx 리버스 프록시 및 Certbot
- **위치**: `nginx/`
- **주요 파일**:
    - **conf.d/default.conf**  
      ACME 챌린지 파일 제공 및 Kibana 프록시 요청을 처리하기 위한 Nginx 설정 파일입니다.
    - **html/index.html**  
      기본 웹 페이지를 제공합니다.
- **Certbot**:  
  `docker-compose.yml`에 정의된 Certbot 컨테이너가 자동으로 Let's Encrypt 인증서를 갱신합니다.

#### Zeek 네트워크 모니터링
- **위치**: `zeek/`
- **주요 파일**:
    - **Dockerfile**  
      Ubuntu 22.04 기반 컨테이너에 Zeek, `librdkafka`, `zeek-kafka` 플러그인을 설치하여 네트워크 트래픽을 캡처합니다.
    - **zeek.cfg**  
      Zeek 설정 파일로, 필요한 스크립트를 로드합니다.
    - **scripts/InferenceKafka.zeek**  
      네트워크 플로우 데이터를 Kafka로 전송하는 Zeek 스크립트 모듈입니다.
    - **local.zeek**  
      Zeek의 로컬 설정(로그 디렉터리, Kafka 설정 등)을 포함합니다.

#### 핵심 서비스: Kafka, Zookeeper, Elasticsearch & Kibana
- **관리**: `docker-compose.yml`에 의해 관리됩니다.
- **서비스**:
    - **Zookeeper**: Kafka 브로커를 조정합니다.
    - **Kafka**: 데이터 메시징과 수집을 처리합니다.
    - **Elasticsearch**: 데이터를 인덱싱하고 저장합니다.
    - **Kibana**: 데이터를 시각화하는 사용자 인터페이스를 제공합니다.

### 설치 및 설정

#### 사전 준비 사항
- Docker 및 Docker Compose가 설치되어 있어야 합니다.
- 호스트에 다음 디렉터리를 생성합니다:
    - `datasets` — 학습 데이터를 위한 디렉터리 (예: CIC-DDoS2019 CSV 파일)
    - `models` — 학습된 모델과 스케일러를 저장할 디렉터리
    - `zeek/logs` — Zeek 로그 저장 디렉터리
    - `nginx/conf.d` — Nginx 설정 파일 디렉터리
    - `nginx/html` — Nginx 웹 콘텐츠 디렉터리

#### 저장소 설정
1. 저장소를 클론합니다:
    ```bash
    git clone <repository-url>
    cd <repository-directory>
    ```
2. 필요에 따라 `docker-compose.yml` 파일에서 도메인, 포트 등의 설정을 수정합니다.

### 실행 가이드

1. **모든 컨테이너 빌드 및 실행:**
    ```bash
    docker-compose up --build
    ```
2. **(선택 사항) AI 모델 학습 실행:**
    학습 데이터셋이 `datasets` 디렉터리에 있는지 확인한 후, 다음 명령을 실행합니다:
    ```bash
    docker-compose run trainer
    ```
3. **Kibana 접근:**
    - HTTP: [http://lcs9317.ddns.net:8080](http://lcs9317.ddns.net:8080)
    - HTTPS: [https://lcs9317.ddns.net](https://lcs9317.ddns.net)

### 네트워킹 및 볼륨 구성

- **네트워킹**:  
  모든 서비스는 `kafka_network` Docker 브리지 네트워크를 통해 통신합니다.
- **볼륨**:
    - `zeek/logs`: Zeek 로그 데이터를 지속적으로 저장합니다.
    - `models`: Trainer와 Inference 컨테이너 간 모델 및 스케일러를 공유합니다.
    - `datasets`: AI 학습용 데이터를 포함합니다.
    - `nginx` 관련 디렉터리: Nginx 설정, 웹 콘텐츠 및 인증서 데이터를 저장합니다.

### 주의사항 및 권장사항

- **네트워크 설정**:  
  호스트 네트워크가 컨테이너 간 통신을 허용하는지 확인합니다.
- **도메인 설정**:  
  도메인(예: `lcs9317.ddns.net`)이 올바르게 구성되어 있는지 확인합니다.
- **자원 할당**:  
  필요에 따라 `docker-compose.yml` 파일에서 메모리 및 CPU 제한을 조정합니다.
- **보안 강화**:  
  프로덕션 환경에서는 Kafka, Elasticsearch, Kibana 등의 보안 설정을 추가로 강화합니다.
- **모니터링**:  
  정기적으로 로그와 성능 지표를 확인하여 안정적인 운영을 유지합니다.

---

이 매뉴얼을 참고하여 분산 DDoS 탐지 시스템을 설치, 구성 및 운영하시기 바랍니다.  
문의사항이나 개선 사항은 프로젝트 이슈 트래커를 통해 남겨주세요.
