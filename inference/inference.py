import os
import time
import json
import numpy as np
from confluent_kafka import Consumer, KafkaError
from elasticsearch import Elasticsearch
from tensorflow.keras.models import load_model
import joblib

KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:29092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "network-traffic")
ES_HOST = os.getenv("ELASTICSEARCH_HOST", "elasticsearch")
ES_PORT = int(os.getenv("ELASTICSEARCH_PORT", "9200"))

MODEL_PATH = "/app/models/ddos_model.h5"
SCALER_PATH = "/app/models/scaler.pkl"

# CNN 사용 시, MODEL_TYPE="cnn" -> MODEL_PATH="/app/models/ddos_cnn_model.h5", etc.
MODEL_TYPE = os.getenv("MODEL_TYPE", "lstm")
if MODEL_TYPE.lower() == "cnn":
    MODEL_PATH = "/app/models/ddos_cnn_model.h5"

def main():
    model = load_model(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)

    consumer = Consumer({
        'bootstrap.servers': KAFKA_BOOTSTRAP_SERVERS,
        'group.id': 'ai-inference-group',
        'auto.offset.reset': 'latest'
    })
    consumer.subscribe([KAFKA_TOPIC])

    es = Elasticsearch([{"host": ES_HOST, "port": ES_PORT, "scheme": "http"}])

    print(f"[INFO] Inference start. MODEL={MODEL_TYPE}, TOPIC={KAFKA_TOPIC}")

    try:
        while True:
            msg = consumer.poll(1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                else:
                    print("[ERROR] Kafka error:", msg.error())
                    break

            data = json.loads(msg.value().decode('utf-8'))
            # 예: 'features' 키가 없다면, 여기서는 임시로 basic feature set 사용
            # 실제로는 collector -> inference로 보내는 데이터 구조를 맞춰주어야 함
            # 아래는 'features'라는 필드가 없을 경우 스킵
            features = data.get("features", None)
            if not features:
                # 만약 'src_ip', 'dst_ip' 등만 있는 raw 패킷이면 -> 전처리 로직 추가 필요
                continue

            # 스케일링 후 모델 입력 형태 변환
            features_np = np.array(features).reshape(1, -1)
            scaled = scaler.transform(features_np)
            if MODEL_TYPE.lower() == "cnn":
                scaled = scaled.reshape((scaled.shape[0], scaled.shape[1], 1))
            else:
                scaled = scaled.reshape((scaled.shape[0], 1, scaled.shape[1]))

            prediction = model.predict(scaled)
            is_ddos = int((prediction > 0.5).astype(int)[0][0])

            doc = {
                "src_ip": data.get("src_ip", ""),
                "dst_ip": data.get("dst_ip", ""),
                "protocol": data.get("protocol", ""),
                "length": data.get("length", ""),
                "prediction": is_ddos,
                "timestamp": int(time.time() * 1000)
            }
            es.index(index="ddos-detection", body=doc)
            print("[INFO] Indexed to ddos-detection:", doc)

    except KeyboardInterrupt:
        pass
    finally:
        consumer.close()

if __name__ == "__main__":
    main()
