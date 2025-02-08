# zeek/Dockerfile

FROM ubuntu:22.04
USER root

# 1. 기본 도구 및 Python 설치
RUN apt-get update && apt-get install -y --no-install-recommends \
    gnupg \
    ca-certificates \
    curl \
    apt-transport-https \
    python3 \
    python3-pip \
 && rm -rf /var/lib/apt/lists/*



# 2. Zeek 공식 OBS 저장소 추가
RUN curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key \
    | gpg --dearmor \
    | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
RUN echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' \
    | tee /etc/apt/sources.list.d/security:zeek.list

# 3. Zeek 및 빌드 도구 설치
RUN apt-get update && apt-get install -y --no-install-recommends \
    zeek \
    cmake \
    make \
    g++ \
    git \
    pkg-config \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# 4. librdkafka v1.4.4 소스 설치 (공식 테스트 버전)
RUN curl -L https://github.com/edenhill/librdkafka/archive/v1.4.4.tar.gz \
    | tar xvz && \
    cd librdkafka-1.4.4 && \
    ./configure && make && make install

# 5. 라이브러리 캐시 업데이트 및 PATH 설정
RUN ldconfig
ENV PATH="$PATH:/opt/zeek/bin"
# LIBRDKAFKA_ROOT 환경변수를 librdkafka가 설치된 기본 경로로 설정
ENV LIBRDKAFKA_ROOT=/usr/local


RUN git clone https://github.com/SeisoLLC/zeek-kafka.git /opt/zeek-kafka && \
    cd /opt/zeek-kafka && \
    git checkout v1.2.0 && \
    ./configure --with-librdkafka=$LIBRDKAFKA_ROOT && \
    make && \
    make install && \
    ldconfig


RUN apt-get update && apt-get install -y netcat-openbsd
RUN apt-get update && apt-get install -y net-tools
# 7. 작업 디렉토리 설정 및 사용자 Zeek 스크립트 복사
WORKDIR /opt/zeek/share/zeek/site
COPY scripts/InferenceKafka.zeek .

COPY zeek.cfg /etc/zeek/zeek.cfg
COPY scripts/local.zeek .

ENV ZEEK_LOG_DIR=/opt/zeek/logs

# 8. 컨테이너 시작 시 Zeek 실행 (네트워크 인터페이스는 필요에 따라 변경)
CMD zeekctl deploy && tail -f /dev/null
