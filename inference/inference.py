# File: inference/inference.py

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

MODEL_TYPE = os.getenv("MODEL_TYPE", "lstm")
MODEL_PATH = "/app/models/ddos_model.h5"
SCALER_PATH = "/app/models/scaler.pkl"

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

            # features 순서는 KafkaSend.zeek에서 전송한 JSON key 순서와 동일해야 합니다.
            features = [
                float(data.get("Flow Duration", 0)),
                float(data.get("Total Fwd Packets", 0)),
                float(data.get("Total Backward Packets", 0)),
                float(data.get("Total Length of Fwd Packets", 0)),
                float(data.get("Total Length of Bwd Packets", 0)),
                float(data.get("Fwd Packet Length Max", 0)),
                float(data.get("Fwd Packet Length Min", 0)),
                float(data.get("Fwd Packet Length Mean", 0)),
                float(data.get("Fwd Packet Length Std", 0)),
                float(data.get("Bwd Packet Length Max", 0)),
                float(data.get("Bwd Packet Length Min", 0)),
                float(data.get("Bwd Packet Length Mean", 0)),
                float(data.get("Bwd Packet Length Std", 0)),
                float(data.get("Flow Bytes/s", 0)),
                float(data.get("Flow Packets/s", 0)),
                float(data.get("Flow IAT Mean", 0)),
                float(data.get("Flow IAT Std", 0)),
                float(data.get("Flow IAT Max", 0)),
                float(data.get("Flow IAT Min", 0)),
                float(data.get("Fwd IAT Total", 0)),   # 추가: Fwd IAT Total
                float(data.get("Fwd IAT Mean", 0)),
                float(data.get("Fwd IAT Std", 0)),
                float(data.get("Fwd IAT Max", 0)),
                float(data.get("Fwd IAT Min", 0)),
                float(data.get("Bwd IAT Total", 0)),   # 추가: Bwd IAT Total
                float(data.get("Bwd IAT Mean", 0)),
                float(data.get("Bwd IAT Std", 0)),
                float(data.get("Bwd IAT Max", 0)),
                float(data.get("Bwd IAT Min", 0)),
                float(data.get("Fwd PSH Flags", 0)),
                float(data.get("Bwd PSH Flags", 0)),
                float(data.get("Fwd URG Flags", 0)),
                float(data.get("Bwd URG Flags", 0)),
                float(data.get("Fwd Header Length", 0)),
                float(data.get("Bwd Header Length", 0)),
                float(data.get("Fwd Packets/s", 0)),
                float(data.get("Bwd Packets/s", 0)),
                float(data.get("Min Packet Length", 0)),
                float(data.get("Max Packet Length", 0)),
                float(data.get("Packet Length Mean", 0)),
                float(data.get("Packet Length Std", 0)),
                float(data.get("Packet Length Variance", 0)),
                float(data.get("FIN Flag Count", 0)),
                float(data.get("SYN Flag Count", 0)),
                float(data.get("RST Flag Count", 0)),
                float(data.get("PSH Flag Count", 0)),
                float(data.get("ACK Flag Count", 0)),
                float(data.get("URG Flag Count", 0)),
                float(data.get("CWE Flag Count", 0)),
                float(data.get("ECE Flag Count", 0)),
                float(data.get("Down/Up Ratio", 0)),
                float(data.get("Average Packet Size", 0)),
                float(data.get("Avg Fwd Segment Size", 0)),
                float(data.get("Avg Bwd Segment Size", 0)),
                float(data.get("Fwd Header Length2", 0)),  # 추가: 두 번째 Fwd Header Length
                float(data.get("Fwd Avg Bytes/Bulk", 0)),
                float(data.get("Fwd Avg Packets/Bulk", 0)),
                float(data.get("Fwd Avg Bulk Rate", 0)),
                float(data.get("Bwd Avg Bytes/Bulk", 0)),
                float(data.get("Bwd Avg Packets/Bulk", 0)),
                float(data.get("Bwd Avg Bulk Rate", 0)),
                float(data.get("Subflow Fwd Packets", 0)),
                float(data.get("Subflow Fwd Bytes", 0)),
                float(data.get("Subflow Bwd Packets", 0)),
                float(data.get("Subflow Bwd Bytes", 0)),
                float(data.get("Init_Win_bytes_forward", 0)),
                float(data.get("Init_Win_bytes_backward", 0)),
                float(data.get("act_data_pkt_fwd", 0)),
                float(data.get("min_seg_size_forward", 0)),
                float(data.get("Active Mean", 0)),
                float(data.get("Active Std", 0)),
                float(data.get("Active Max", 0)),
                float(data.get("Active Min", 0)),
                float(data.get("Idle Mean", 0)),
                float(data.get("Idle Std", 0)),
                float(data.get("Idle Max", 0)),
                float(data.get("Idle Min", 0))
            ]


            features = [float(x) for x in features]
            arr = np.array(features).reshape(1, -1)
            arr_scaled = scaler.transform(arr)

            if MODEL_TYPE.lower() == "cnn":
                arr_scaled = arr_scaled.reshape((arr_scaled.shape[0], arr_scaled.shape[1], 1))
            else:
                arr_scaled = arr_scaled.reshape((arr_scaled.shape[0], 1, arr_scaled.shape[1]))

            pred = model.predict(arr_scaled)
            is_ddos = int((pred > 0.5).astype(int)[0][0])

            doc = {
                "FlowID": data.get("FlowID", ""),
                "SourceIP": str(data.get("Source IP", "")),
                "DestinationIP": str(data.get("Destination IP", "")),
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
