# AI기반 DDoS탐지 및 네트워크 트래픽 관제 시스템

본 프로젝트는 **Docker** 기반으로 배포용으로 만들어진 프로그램이다.

## 설치전 필요 요소

- 리눅스 기준이며 docker compose가 설치되어 있어야 한다.
- 본인이 가지고 있는 dns주소가 준비되어야 한다.


## 설치법

    git clone https://github.com/lcs9317/SOC

/nginx/conf.d/default.conf 파일에 본인이 만든 dns주소 기입

**주소기입시 유의사항)** 이 프로젝트는 wsl기준으로 만들어졌기에 8080포트를 사용하지만
리눅스 사용유저라면 80포트로 수정하여 사용한다.

wsl사용 유저만 cmd에서 순서대로 입력

    netsh interface portproxy add v4tov4 listenport=80 listenaddress=0.0.0.0 connectport=8080 connectaddress=[WSL의 IP]

    docker-compose build 

    docker-compose up -d

그 후

Kibana(https://mydns.url.com) 에 접속하여 kibana가 접속되는지 확인

접속이 안된다면 프로젝트 창에서

    docker exec -it elasticsearch bash

    bin/elasticsearch-service-tokens create elastic/kibana 토큰이름

출력되는 토큰을 docker-compose.yml 파일의 environment란에 복사 후 
 
    docker-compose down
    docker-compose up -d

kibana로 재접속하여 discover 탭에서 네트워크 로그 관측

### DDoS탐지
좌측 Management 탭 > Kibana > Data Views > Data Create 선택

타입으로 date 선택 후 아래 스크립트를 추가
```
if (doc['timestamp'].size() != 0) {
  emit(doc['timestamp'].value);
}
```


그 후 Visualize 탭에서 실시간으로 탐지


### 사용 컨테이너
1. zeek : zeek-kafka 플러그인을 통한 로그 kafka로 전송
2. kafka : apache기반 서버로 클러스터 내부 브로커를 통해 특정 토픽의 elasticsearch로 로그전송
3. elasticsearch : kafka의 브로커에서 전송된 json형태의 로그파일을 실시간 저장
4. logstash : kafka와 elasticsearch의 중간에서 데이터 변환 및 전송
5. kibana : elasticsearch에 저장된 데이터 시각화
6. nginx : ddns 및 ssl 인증 
7. zookeeper : 프로세스간의 동기화 기능
8. certbot : ssl 인증 갱신
9. python : AI 학습 및 모델기반 DDoS탐지 

### AI 기능
tensorflow : AI모델 학습 Python 라이브러리
keras : Python 라이브러리로 tensorflow 모델 학습을 강화
