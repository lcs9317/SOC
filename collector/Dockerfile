FROM python:3.9-slim

WORKDIR /app

RUN apt-get update && apt-get install -y ca-certificates
RUN update-ca-certificates

# 필요한 시스템 패키지 설치 (libpcap 등)
RUN apt-get update && \
    apt-get install -y libpcap-dev && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY network_collector.py .

CMD ["python", "network_collector.py"]
