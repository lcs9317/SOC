@load packages/zeek-kafka

module InferenceKafka;

export {
    type FlowFeatures: record {
        flow_duration            : double &log;
        total_fwd_packets        : double &log;
        total_bwd_packets        : double &log;
        total_length_fwd_packets : double &log;
        total_length_bwd_packets : double &log;
        fwd_packet_length_max    : double &log;
        fwd_packet_length_min    : double &log;
        fwd_packet_length_mean   : double &log;
        fwd_packet_length_std    : double &log;
        bwd_packet_length_max    : double &log;
        bwd_packet_length_min    : double &log;
        bwd_packet_length_mean   : double &log;
        bwd_packet_length_std    : double &log;
        flow_bytes_per_sec       : double &log;
        flow_packets_per_sec     : double &log;
        flow_iat_mean            : double &log;
        flow_iat_std             : double &log;
        flow_iat_max             : double &log;
        flow_iat_min             : double &log;
        fwd_iat_total            : double &log;  
        fwd_iat_mean             : double &log;
        fwd_iat_std              : double &log;
        fwd_iat_max              : double &log;
        fwd_iat_min              : double &log;
        bwd_iat_total            : double &log;  
        bwd_iat_mean             : double &log;
        bwd_iat_std              : double &log;
        bwd_iat_max              : double &log;
        bwd_iat_min              : double &log;
        fwd_psh_flags            : double &log;
        bwd_psh_flags            : double &log;
        fwd_urg_flags            : double &log;
        bwd_urg_flags            : double &log;
        fwd_header_length        : double &log;
        bwd_header_length        : double &log;
        fwd_packets_per_sec2     : double &log;
        bwd_packets_per_sec2     : double &log;
        min_packet_length        : double &log;
        max_packet_length        : double &log;
        packet_length_mean       : double &log;
        packet_length_std        : double &log;
        packet_length_variance   : double &log;
        fin_flag_count           : double &log;
        syn_flag_count           : double &log;
        rst_flag_count           : double &log;
        psh_flag_count           : double &log;
        ack_flag_count           : double &log;
        urg_flag_count           : double &log;
        cwe_flag_count           : double &log;
        ece_flag_count           : double &log;
        down_up_ratio            : double &log;
        average_packet_size      : double &log;
        avg_fwd_segment_size     : double &log;
        avg_bwd_segment_size     : double &log;
        fwd_header_length2       : double &log;
        fwd_avg_bytes_bulk       : double &log;
        fwd_avg_packets_bulk     : double &log;
        fwd_avg_bulk_rate        : double &log;
        bwd_avg_bytes_bulk       : double &log;
        bwd_avg_packets_bulk     : double &log;
        bwd_avg_bulk_rate        : double &log;
        subflow_fwd_packets      : double &log;
        subflow_fwd_bytes        : double &log;
        subflow_bwd_packets      : double &log;
        subflow_bwd_bytes        : double &log;
        init_win_bytes_forward   : double &log;
        init_win_bytes_backward  : double &log;
        act_data_pkt_fwd         : double &log;
        min_seg_size_forward     : double &log;
        active_mean              : double &log;
        active_std               : double &log;
        active_max               : double &log;
        active_min               : double &log;
        idle_mean                : double &log;
        idle_std                 : double &log;
        idle_max                 : double &log;
        idle_min                 : double &log;
        flow_id                  : string &log;
        source_ip                : string &log;
        destination_ip           : string &log;
    };
}


# 2) Log::ID에 FLOW_FEATURES 추가
redef enum Log::ID += { FLOW_FEATURES };

# (옵션) 전역 Log::Stream 생성 – Log::write 호출 시에는 로그 ID(FLOW_FEATURES)를 사용합니다.
global flow_features_log = Log::create_stream(
    FLOW_FEATURES,
    [
        $columns = FlowFeatures,
        $path    = "flow-features"
    ]
);

event zeek_init() &priority=-10 {
    # Kafka로 전송하기 위한 Log::Filter 정의
    local flow_filter: Log::Filter = [
        $name   = "kafka-flowfeatures",
        $writer = Log::WRITER_KAFKAWRITER,
        $path   = "network-traffic",
        $config = table(
            ["metadata.broker.list"] = "localhost:9092",
            ["topic_name"]           = "network-traffic"
        )
    ];
    Log::add_filter(FLOW_FEATURES, flow_filter);
}

#
# [방법 2] 권장하는 방법:
# Conn::log_conn 이벤트를 활용하여 Conn::Info 레코드(rec)에서
# 원본 및 응답 통계 값을 추출한 후 FlowFeatures 레코드에 할당하고 Kafka로 전송합니다.
#
event Conn::log_conn(rec: Conn::Info) {
    local total_fwd_packets        = rec$orig_pkts + 0.0;
    local total_length_fwd_packets = rec$orig_bytes + 0.0;
    local total_bwd_packets        = rec$resp_pkts + 0.0;
    local total_length_bwd_packets = rec$resp_bytes + 0.0;

    local f: FlowFeatures = [
        $flow_duration            = rec$duration / 1sec,
        $total_fwd_packets        = total_fwd_packets,
        $total_length_fwd_packets = total_length_fwd_packets,
        $total_bwd_packets        = total_bwd_packets,
        $total_length_bwd_packets = total_length_bwd_packets,
        # 나머지 필드는 0.0으로 초기화 (필요에 따라 추가 계산 로직을 넣으세요)
        $fwd_packet_length_max    = 0.0,
        $fwd_packet_length_min    = 0.0,
        $fwd_packet_length_mean   = 0.0,
        $fwd_packet_length_std    = 0.0,
        $bwd_packet_length_max    = 0.0,
        $bwd_packet_length_min    = 0.0,
        $bwd_packet_length_mean   = 0.0,
        $bwd_packet_length_std    = 0.0,
        $flow_bytes_per_sec       = 0.0,
        $flow_packets_per_sec     = 0.0,
        $flow_iat_mean            = 0.0,
        $flow_iat_std             = 0.0,
        $flow_iat_max             = 0.0,
        $flow_iat_min             = 0.0,
        $fwd_iat_total            = 0.0,
        $fwd_iat_mean             = 0.0,
        $fwd_iat_std              = 0.0,
        $fwd_iat_max              = 0.0,
        $fwd_iat_min              = 0.0,
        $bwd_iat_total            = 0.0,
        $bwd_iat_mean             = 0.0,
        $bwd_iat_std              = 0.0,
        $bwd_iat_max              = 0.0,
        $bwd_iat_min              = 0.0,
        $fwd_psh_flags            = 0.0,
        $bwd_psh_flags            = 0.0,
        $fwd_urg_flags            = 0.0,
        $bwd_urg_flags            = 0.0,
        $fwd_header_length        = 0.0,
        $bwd_header_length        = 0.0,
        $fwd_packets_per_sec2     = 0.0,
        $bwd_packets_per_sec2     = 0.0,
        $min_packet_length        = 0.0,
        $max_packet_length        = 0.0,
        $packet_length_mean       = 0.0,
        $packet_length_std        = 0.0,
        $packet_length_variance   = 0.0,
        $fin_flag_count           = 0.0,
        $syn_flag_count           = 0.0,
        $rst_flag_count           = 0.0,
        $psh_flag_count           = 0.0,
        $ack_flag_count           = 0.0,
        $urg_flag_count           = 0.0,
        $cwe_flag_count           = 0.0,
        $ece_flag_count           = 0.0,
        $down_up_ratio            = 0.0,
        $average_packet_size      = 0.0,
        $avg_fwd_segment_size     = 0.0,
        $avg_bwd_segment_size     = 0.0,
        $fwd_header_length2       = 0.0,
        $fwd_avg_bytes_bulk       = 0.0,
        $fwd_avg_packets_bulk     = 0.0,
        $fwd_avg_bulk_rate        = 0.0,
        $bwd_avg_bytes_bulk       = 0.0,
        $bwd_avg_packets_bulk     = 0.0,
        $bwd_avg_bulk_rate        = 0.0,
        $subflow_fwd_packets      = 0.0,
        $subflow_fwd_bytes        = 0.0,
        $subflow_bwd_packets      = 0.0,
        $subflow_bwd_bytes        = 0.0,
        $init_win_bytes_forward   = 0.0,
        $init_win_bytes_backward  = 0.0,
        $act_data_pkt_fwd         = 0.0,
        $min_seg_size_forward     = 0.0,
        $active_mean              = 0.0,
        $active_std               = 0.0,
        $active_max               = 0.0,
        $active_min               = 0.0,
        $idle_mean                = 0.0,
        $idle_std                 = 0.0,
        $idle_max                 = 0.0,
        $idle_min                 = 0.0,
        $flow_id                  = rec$uid,
        $source_ip                = fmt("%s", rec$id$orig_h),
        $destination_ip           = fmt("%s", rec$id$resp_h)
    ];
    Log::write(FLOW_FEATURES, f);
}

