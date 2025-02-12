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
ES_USERNAME = os.getenv("ELASTICSEARCH_USERNAME", "elastic")
ES_PASSWORD = os.getenv("ELASTICSEARCH_PASSWORD", "root")

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

    es = Elasticsearch([{"host": ES_HOST, "port": ES_PORT, "scheme": "http"}],
                       http_auth=(ES_USERNAME, ES_PASSWORD)
                       )
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
            print("[DEBUG] Raw data keys:", list(data.keys()))
            if "network-traffic" in data:
                data = data["network-traffic"]
          

            # features 배열: Zeek에서 전송한 JSON의 key들이 모두 소문자와 밑줄 형식입니다.
            features = [
                float(data.get("flow_duration", 0)),
                float(data.get("total_fwd_packets", 0)),
                float(data.get("total_bwd_packets", 0)),
                float(data.get("total_length_fwd_packets", 0)),
                float(data.get("total_length_bwd_packets", 0)),
                float(data.get("fwd_packet_length_max", 0)),
                float(data.get("fwd_packet_length_min", 0)),
                float(data.get("fwd_packet_length_mean", 0)),
                float(data.get("fwd_packet_length_std", 0)),
                float(data.get("bwd_packet_length_max", 0)),
                float(data.get("bwd_packet_length_min", 0)),
                float(data.get("bwd_packet_length_mean", 0)),
                float(data.get("bwd_packet_length_std", 0)),
                float(data.get("flow_bytes_per_sec", 0)),
                float(data.get("flow_packets_per_sec", 0)),
                float(data.get("flow_iat_mean", 0)),
                float(data.get("flow_iat_std", 0)),
                float(data.get("flow_iat_max", 0)),
                float(data.get("flow_iat_min", 0)),
                float(data.get("fwd_iat_total", 0)),
                float(data.get("fwd_iat_mean", 0)),
                float(data.get("fwd_iat_std", 0)),
                float(data.get("fwd_iat_max", 0)),
                float(data.get("fwd_iat_min", 0)),
                float(data.get("bwd_iat_total", 0)),
                float(data.get("bwd_iat_mean", 0)),
                float(data.get("bwd_iat_std", 0)),
                float(data.get("bwd_iat_max", 0)),
                float(data.get("bwd_iat_min", 0)),
                float(data.get("fwd_psh_flags", 0)),
                float(data.get("bwd_psh_flags", 0)),
                float(data.get("fwd_urg_flags", 0)),
                float(data.get("bwd_urg_flags", 0)),
                float(data.get("fwd_header_length", 0)),
                float(data.get("bwd_header_length", 0)),
                float(data.get("fwd_packets_per_sec", 0)),
                float(data.get("bwd_packets_per_sec", 0)),
                float(data.get("min_packet_length", 0)),
                float(data.get("max_packet_length", 0)),
                float(data.get("packet_length_mean", 0)),
                float(data.get("packet_length_std", 0)),
                float(data.get("packet_length_variance", 0)),
                float(data.get("fin_flag_count", 0)),
                float(data.get("syn_flag_count", 0)),
                float(data.get("rst_flag_count", 0)),
                float(data.get("psh_flag_count", 0)),
                float(data.get("ack_flag_count", 0)),
                float(data.get("urg_flag_count", 0)),
                float(data.get("cwe_flag_count", 0)),
                float(data.get("ece_flag_count", 0)),
                float(data.get("down_up_ratio", 0)),
                float(data.get("average_packet_size", 0)),
                float(data.get("avg_fwd_segment_size", 0)),
                float(data.get("avg_bwd_segment_size", 0)),
                float(data.get("fwd_header_length2", 0)),
                float(data.get("fwd_avg_bytes_bulk", 0)),
                float(data.get("fwd_avg_packets_bulk", 0)),
                float(data.get("fwd_avg_bulk_rate", 0)),
                float(data.get("bwd_avg_bytes_bulk", 0)),
                float(data.get("bwd_avg_packets_bulk", 0)),
                float(data.get("bwd_avg_bulk_rate", 0)),
                float(data.get("subflow_fwd_packets", 0)),
                float(data.get("subflow_fwd_bytes", 0)),
                float(data.get("subflow_bwd_packets", 0)),
                float(data.get("subflow_bwd_bytes", 0)),
                float(data.get("init_win_bytes_forward", 0)),
                float(data.get("init_win_bytes_backward", 0)),
                float(data.get("act_data_pkt_fwd", 0)),
                float(data.get("min_seg_size_forward", 0)),
                float(data.get("active_mean", 0)),
                float(data.get("active_std", 0)),
                float(data.get("active_max", 0)),
                float(data.get("active_min", 0)),
                float(data.get("idle_mean", 0)),
                float(data.get("idle_std", 0)),
                float(data.get("idle_max", 0)),
                float(data.get("idle_min", 0))
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

            # 인덱싱할 문서를 Zeek 파일의 칼럼명(언더바 사용)과 일치하도록 구성합니다.
            doc = {
                "flow_id": data.get("flow_id", ""),
                "source_ip": str(data.get("source_ip", "")),
                "destination_ip": str(data.get("destination_ip", "")),
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
