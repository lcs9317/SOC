# 예: TensorFlow CPU 버전
FROM tensorflow/tensorflow:latest
WORKDIR /app

RUN apt-get update && apt-get install -y ca-certificates
RUN update-ca-certificates

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY trainer.py .

CMD ["python", "trainer.py"]
