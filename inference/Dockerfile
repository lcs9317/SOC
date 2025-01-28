FROM tensorflow/tensorflow:latest
WORKDIR /app

RUN apt-get update && apt-get install -y ca-certificates
RUN update-ca-certificates

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY inference.py .

CMD ["python", "inference.py"]
