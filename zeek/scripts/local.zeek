@load packages/zeek-kafka
@load InferenceKafka.zeek

# 로그 파일이 /opt/zeek/logs에 생성되도록 재정의
redef Log::default_logdir = "/opt/zeek/logs";


redef Kafka::kafka_conf = table(
    ["metadata.broker.list"] = "localhost:9092"
);

redef Kafka::tag_json = T;

redef Kafka::max_wait_on_shutdown = 3000;

redef Kafka::topic_name = "network-traffic";
