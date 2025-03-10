import os
import time
import json
import numpy as np
from confluent_kafka import Consumer, KafkaError
from elasticsearch import Elasticsearch
from tensorflow.keras.models import load_model
import joblib

# 환경 변수 설정
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

def extract_features(data_dict, model_type="lstm"):
    """
    딕셔너리 형태의 네트워크 트래픽 정보를 입력 받아,
    모델 추론에 필요한 피처 벡터(NumPy 배열)를 생성해 반환.
    """
    # main() 내부에서 하던 feature 리스트 구성 로직을 그대로 옮겨옴
    features = [
        float(data_dict.get("flow_duration", 0)),
        float(data_dict.get("total_fwd_packets", 0)),
        float(data_dict.get("total_bwd_packets", 0)),
        float(data_dict.get("total_length_fwd_packets", 0)),
        float(data_dict.get("total_length_bwd_packets", 0)),
        float(data_dict.get("fwd_packet_length_max", 0)),
        float(data_dict.get("fwd_packet_length_min", 0)),
        float(data_dict.get("fwd_packet_length_mean", 0)),
        float(data_dict.get("fwd_packet_length_std", 0)),
        float(data_dict.get("bwd_packet_length_max", 0)),
        float(data_dict.get("bwd_packet_length_min", 0)),
        float(data_dict.get("bwd_packet_length_mean", 0)),
        float(data_dict.get("bwd_packet_length_std", 0)),
        float(data_dict.get("flow_bytes_per_sec", 0)),
        float(data_dict.get("flow_packets_per_sec", 0)),
        float(data_dict.get("flow_iat_mean", 0)),
        float(data_dict.get("flow_iat_std", 0)),
        float(data_dict.get("flow_iat_max", 0)),
        float(data_dict.get("flow_iat_min", 0)),
        float(data_dict.get("fwd_iat_total", 0)),
        float(data_dict.get("fwd_iat_mean", 0)),
        float(data_dict.get("fwd_iat_std", 0)),
        float(data_dict.get("fwd_iat_max", 0)),
        float(data_dict.get("fwd_iat_min", 0)),
        float(data_dict.get("bwd_iat_total", 0)),
        float(data_dict.get("bwd_iat_mean", 0)),
        float(data_dict.get("bwd_iat_std", 0)),
        float(data_dict.get("bwd_iat_max", 0)),
        float(data_dict.get("bwd_iat_min", 0)),
        float(data_dict.get("fwd_psh_flags", 0)),
        float(data_dict.get("bwd_psh_flags", 0)),
        float(data_dict.get("fwd_urg_flags", 0)),
        float(data_dict.get("bwd_urg_flags", 0)),
        float(data_dict.get("fwd_header_length", 0)),
        float(data_dict.get("bwd_header_length", 0)),
        float(data_dict.get("fwd_packets_per_sec", 0)),
        float(data_dict.get("bwd_packets_per_sec", 0)),
        float(data_dict.get("min_packet_length", 0)),
        float(data_dict.get("max_packet_length", 0)),
        float(data_dict.get("packet_length_mean", 0)),
        float(data_dict.get("packet_length_std", 0)),
        float(data_dict.get("packet_length_variance", 0)),
        float(data_dict.get("fin_flag_count", 0)),
        float(data_dict.get("syn_flag_count", 0)),
        float(data_dict.get("rst_flag_count", 0)),
        float(data_dict.get("psh_flag_count", 0)),
        float(data_dict.get("ack_flag_count", 0)),
        float(data_dict.get("urg_flag_count", 0)),
        float(data_dict.get("cwe_flag_count", 0)),
        float(data_dict.get("ece_flag_count", 0)),
        float(data_dict.get("down_up_ratio", 0)),
        float(data_dict.get("average_packet_size", 0)),
        float(data_dict.get("avg_fwd_segment_size", 0)),
        float(data_dict.get("avg_bwd_segment_size", 0)),
        float(data_dict.get("fwd_header_length2", 0)),
        float(data_dict.get("fwd_avg_bytes_bulk", 0)),
        float(data_dict.get("fwd_avg_packets_bulk", 0)),
        float(data_dict.get("fwd_avg_bulk_rate", 0)),
        float(data_dict.get("bwd_avg_bytes_bulk", 0)),
        float(data_dict.get("bwd_avg_packets_bulk", 0)),
        float(data_dict.get("bwd_avg_bulk_rate", 0)),
        float(data_dict.get("subflow_fwd_packets", 0)),
        float(data_dict.get("subflow_fwd_bytes", 0)),
        float(data_dict.get("subflow_bwd_packets", 0)),
        float(data_dict.get("subflow_bwd_bytes", 0)),
        float(data_dict.get("init_win_bytes_forward", 0)),
        float(data_dict.get("init_win_bytes_backward", 0)),
        float(data_dict.get("act_data_pkt_fwd", 0)),
        float(data_dict.get("min_seg_size_forward", 0)),
        float(data_dict.get("active_mean", 0)),
        float(data_dict.get("active_std", 0)),
        float(data_dict.get("active_max", 0)),
        float(data_dict.get("active_min", 0)),
        float(data_dict.get("idle_mean", 0)),
        float(data_dict.get("idle_std", 0)),
        float(data_dict.get("idle_max", 0)),
        float(data_dict.get("idle_min", 0))
    ]

    arr = np.array(features).reshape(1, -1)

    # CNN일 경우 (batch, timesteps, features) 형태가 되도록 reshape할 수도 있으나,
    # 여기서는 '스케일링 전' 반환만 담당하고 main에서 처리
    return arr


def main():
    """
    카프카에서 메시지 받아 모델 추론 → Elasticsearch 인덱싱까지 수행하는 운영 코드
    """
    model = load_model(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)

    consumer = Consumer({
        'bootstrap.servers': KAFKA_BOOTSTRAP_SERVERS,
        'group.id': 'ai-inference-group',
        'auto.offset.reset': 'latest'
    })
    consumer.subscribe([KAFKA_TOPIC])

    es = Elasticsearch(
        [{"host": ES_HOST, "port": ES_PORT, "scheme": "http"}],
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
            if "network-traffic" in data:
                data = data["network-traffic"]

            # 1) 피처 추출
            arr = extract_features(data, model_type=MODEL_TYPE)
            # 2) 스케일링
            arr_scaled = scaler.transform(arr)

            # 3) LSTM/CNN 형태 맞춰 reshape
            if MODEL_TYPE.lower() == "cnn":
                arr_scaled = arr_scaled.reshape((arr_scaled.shape[0], arr_scaled.shape[1], 1))
            else:
                arr_scaled = arr_scaled.reshape((arr_scaled.shape[0], 1, arr_scaled.shape[1]))

            # 4) 추론
            pred = model.predict(arr_scaled)
            is_ddos = int((pred > 0.5).astype(int)[0][0])

            # 5) Elasticsearch 인덱싱
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
