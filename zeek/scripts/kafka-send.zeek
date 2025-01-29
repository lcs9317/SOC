@load policy/protocols/kafka/kafka.zeek
@load base/protocols/conn
@load base/frameworks/packet
@load base/protocols/tcp
@load base/protocols/udp

module KafkaSend;

export {
    global kafka_producer: Kafka::Producer;

    # Per-flow data structure
    # (Flow Key -> record of stats)
    global flow_table: table[string] of FlowData = {};

    # Record to hold all stats needed
    type FlowData: record {
        # Basic identifiers
        flow_id: string;
        source_ip: addr;
        source_port: port;
        dest_ip: addr;
        dest_port: port;
        protocol: transport_proto;
        start_time: time;   # Timestamp of first packet
        end_time: time;     # Timestamp of last packet

        # Packet-level lists (for advanced stats)
        forward_timestamps: vector of time;    # arrival times for forward direction
        forward_lengths: vector of count;      # packet lengths forward
        backward_timestamps: vector of time;
        backward_lengths: vector of count;

        # TCP/UDP flags
        fin_flag_count: count;
        syn_flag_count: count;
        rst_flag_count: count;
        psh_flag_count: count;
        ack_flag_count: count;
        urg_flag_count: count;
        cwe_flag_count: count;    # Zeek doesn't track CWE by default, but let's put placeholder
        ece_flag_count: count;

        # count forward/backward packets
        fwd_pkt_count: count;
        bwd_pkt_count: count;
        # sum lengths
        fwd_bytes_total: count;
        bwd_bytes_total: count;

        # Fwd PSH flags, Bwd PSH flags, Fwd URG flags, Bwd URG flags, etc.
        fwd_psh_flags: count;
        bwd_psh_flags: count;
        fwd_urg_flags: count;
        bwd_urg_flags: count;

        # Fwd Header Length, Bwd Header Length
        fwd_header_len: count;
        bwd_header_len: count;

        # active/idle tracking
        # we'll approximate: whenever there's a gap > some threshold, we consider it "idle"
        # real CIC does more complex definitions. We'll store times in vectors.
        active_periods: vector of interval;
        idle_periods: vector of interval;
        last_packet_time: time;
        is_active: bool;
        active_start: time;
    };
}

# Helper function: get flow key string
function make_flow_key(h: conn_id): string
{
    return fmt("%s:%s-%s:%s-%s",
        h$orig_h, h$orig_p,
        h$resp_h, h$resp_p,
        h$proto);
}

event zeek_init()
{
    local brokers = "kafka:9092";
    kafka_producer = Kafka::Producer(brokers);
    print fmt("Zeek Kafka Producer initialized, brokers=%s", brokers);
}

# 1) Packet-level capture
event raw_packet(p: packet)
{
    # parse IP, ports, etc. from p
    if ( ! p$header?$ip ) return;  # non-IP traffic?
    local ip_hdr = p$header$ip;

    local src = ip_hdr$src;
    local dst = ip_hdr$dst;

    local proto = ip_hdr$proto;
    # This might be 6 for TCP, 17 for UDP, etc.

    # We need to guess the ports
    local sp = 0:p;   # default
    local dp = 0:p;
    local is_tcp = F;
    local is_udp = F;

    # check if there's a TCP header
    if ( p$header?$tcp )
    {
        is_tcp = T;
        sp = p$header$tcp$src_port;
        dp = p$header$tcp$dst_port;
    }
    else if ( p$header?$udp )
    {
        is_udp = T;
        sp = p$header$udp$src_port;
        dp = p$header$udp$dst_port;
    }

    local flow_id = fmt("%s:%s-%s:%s-%s", src, sp, dst, dp, proto);

    if ( flow_table[flow_id] == nil )
    {
        local rec = FlowData(
            flow_id=flow_id,
            source_ip=src, source_port=sp,
            dest_ip=dst, dest_port=dp,
            protocol=if (is_tcp) tcp else if (is_udp) udp else ip,  # approximate
            start_time = network_time(),
            end_time = network_time(),
            forward_timestamps=vector(),
            forward_lengths=vector(),
            backward_timestamps=vector(),
            backward_lengths=vector(),
            fin_flag_count=0, syn_flag_count=0, rst_flag_count=0,
            psh_flag_count=0, ack_flag_count=0, urg_flag_count=0,
            cwe_flag_count=0, ece_flag_count=0,
            fwd_pkt_count=0, bwd_pkt_count=0,
            fwd_bytes_total=0, bwd_bytes_total=0,
            fwd_psh_flags=0, bwd_psh_flags=0,
            fwd_urg_flags=0, bwd_urg_flags=0,
            fwd_header_len=0, bwd_header_len=0,
            active_periods=vector(),
            idle_periods=vector(),
            last_packet_time=network_time(),
            is_active=F,
            active_start=network_time()
        );
        flow_table[flow_id] = rec;
    }

    local fd = flow_table[flow_id];
    fd.end_time = network_time();

    # check direction (forward vs backward)  
    local is_forward = T;  
    # if (src == fd$source_ip && sp == fd$source_port) => forward  
    # else if (src == fd$dest_ip && sp == fd$dest_port) => backward
    if ( src == fd$source_ip && sp == fd$source_port )
        is_forward = T;
    else
        is_forward = F;

    local pkt_len = p$captured_length;  # approximate actual length

    # store timestamps for IAT
    if (is_forward)
    {
        fd$forward_timestamps += network_time();
        fd$forward_lengths += pkt_len;
        fd$fwd_pkt_count += 1;
        fd$fwd_bytes_total += pkt_len;
    }
    else
    {
        fd$backward_timestamps += network_time();
        fd$backward_lengths += pkt_len;
        fd$bwd_pkt_count += 1;
        fd$bwd_bytes_total += pkt_len;
    }

    # parse TCP flags
    if (is_tcp)
    {
        local th = p$header$tcp;
        if ( th$flags & 0x01 != 0 ) fd$fin_flag_count += 1;  # FIN
        if ( th$flags & 0x02 != 0 ) fd$syn_flag_count += 1;  # SYN
        if ( th$flags & 0x04 != 0 ) fd$rst_flag_count += 1;  # RST
        if ( th$flags & 0x08 != 0 )
        {
            fd$psh_flag_count += 1;  # PSH
            if (is_forward)
                fd$fwd_psh_flags += 1;
            else
                fd$bwd_psh_flags += 1;
        }
        if ( th$flags & 0x10 != 0 ) fd$ack_flag_count += 1;  # ACK
        if ( th$flags & 0x20 != 0 )
        {
            fd$urg_flag_count += 1;  # URG
            if (is_forward)
                fd$fwd_urg_flags += 1;
            else
                fd$bwd_urg_flags += 1;
        }
        if ( th$flags & 0x40 != 0 ) fd$ece_flag_count += 1;  # ECE
        # cwe_flag_count는 실제 TCP에는 없으므로, 여기서는 dummy
    }

    # header length (simplistic)
    local ip_header_len = ip_hdr$hlen * 4;
    if (is_tcp)
    {
        local tcp_header_len = p$header$tcp$offset * 4;
        if (is_forward)
            fd$fwd_header_len += ip_header_len + tcp_header_len;
        else
            fd$bwd_header_len += ip_header_len + tcp_header_len;
    }
    else if (is_udp)
    {
        # UDP header = 8 bytes
        if (is_forward)
            fd$fwd_header_len += ip_header_len + 8;
        else
            fd$bwd_header_len += ip_header_len + 8;
    }

    # active/idle tracking
    local gap = network_time() - fd$last_packet_time;
    fd$last_packet_time = network_time();
    # 임의로 gap > 1초면 idle로 본다고 가정(실제 CIC는 다름)
    if ( gap > 1sec )
    {
        # 이전 active 구간을 종료
        if ( fd$is_active )
        {
            local active_dur = network_time() - fd$active_start;
            fd$active_periods += active_dur;
            fd$is_active = F;
        }
        # idle 기간이 얼마인지
        fd$idle_periods += gap;
    }
    else
    {
        # idle이 아닐 때 => active
        if ( ! fd$is_active )
        {
            # 새 active 시작
            fd$active_start = network_time();
            fd$is_active = T;
        }
    }
}

# 2) Flow 종료 시점
event connection_state_remove(c: connection)
{
    local key = make_flow_key(c$id);
    local fd = flow_table[key];
    if ( fd == nil )
        return;  # no data?

    # finalize active/idle
    if ( fd$is_active )
    {
        local active_dur = network_time() - fd$active_start;
        fd$active_periods += active_dur;
        fd$is_active = F;
    }

    # Flow Duration
    local duration = fd$end_time - fd$start_time;

    # Packet length stats
    function compute_stats(vals: vector of count): record(mean: double, std: double, max_v: count, min_v: count) =
    {
        if ( |vals| == 0 )
            return [ mean=0.0, std=0.0, max_v=0, min_v=0 ];
        local s: count = 0;
        local mx: count = 0;
        local mn: count = 999999999;
        for ( i in vals )
        {
            s += vals[i];
            if (vals[i] > mx) mx = vals[i];
            if (vals[i] < mn) mn = vals[i];
        }
        local mean_ = double(s) / double(|vals|);
        # std
        local var_sum = 0.0;
        for ( i in vals )
        {
            local diff = double(vals[i]) - mean_;
            var_sum += diff * diff;
        }
        local variance = var_sum / double(|vals|);
        local std_ = sqrt(variance);
        return [ mean=mean_, std=std_, max_v=mx, min_v=mn ];
    }

    local fwd_stats = compute_stats(fd$forward_lengths);
    local bwd_stats = compute_stats(fd$backward_lengths);

    # IAT stats
    function compute_iat(tms: vector of time): record(mean: interval, std: interval, max_v: interval, min_v: interval) =
    {
        if ( |tms| < 2 )
            return [ mean=0sec, std=0sec, max_v=0sec, min_v=0sec ];

        local intervals: vector of interval = vector();
        # sort timestamps
        local tmp = sort tms;
        for ( i in tmp )
        {
            if ( i == 0 ) continue;
            local gap = tmp[i] - tmp[i-1];
            intervals += gap;
        }

        local total = 0sec;
        local mx: interval = 0sec;
        local mn: interval = 99999999sec;
        for ( i in intervals )
        {
            total += intervals[i];
            if ( intervals[i] > mx ) mx = intervals[i];
            if ( intervals[i] < mn ) mn = intervals[i];
        }
        local mean_i = total / |intervals|;
        # std
        local var_sum = 0.0;
        for ( i in intervals )
        {
            local diff = intervals[i] - mean_i;
            var_sum += diff * diff;
        }
        local variance = var_sum / double(|intervals|);
        local std_i = sqrt(variance);

        return [ mean=mean_i, std=std_i, max_v=mx, min_v=mn ];
    }

    local flow_iat_stats = compute_iat(append(fd$forward_timestamps, fd$backward_timestamps));
    local fwd_iat_stats  = compute_iat(fd$forward_timestamps);
    local bwd_iat_stats  = compute_iat(fd$backward_timestamps);

    # Active/Idle stats
    function compute_interval_stats(vals: vector of interval): record(mean: interval, std: interval, max_v: interval, min_v: interval) =
    {
        if ( |vals| == 0 )
            return [ mean=0sec, std=0sec, max_v=0sec, min_v=0sec ];

        local total = 0sec;
        local mx: interval = 0sec;
        local mn: interval = 99999999sec;
        for ( i in vals )
        {
            total += vals[i];
            if (vals[i] > mx ) mx = vals[i];
            if (vals[i] < mn ) mn = vals[i];
        }
        local mean_ = total / |vals|;
        # std
        local var_sum = 0.0;
        for ( i in vals )
        {
            local diff = vals[i] - mean_;
            var_sum += diff * diff;
        }
        local variance = var_sum / double(|vals|);
        local std_ = sqrt(variance);
        return [ mean=mean_, std=std_, max_v=mx, min_v=mn ];
    }

    local active_s = compute_interval_stats(fd$active_periods);
    local idle_s   = compute_interval_stats(fd$idle_periods);

    local total_pkts = fd$fwd_pkt_count + fd$bwd_pkt_count;
    local total_bytes = fd$fwd_bytes_total + fd$bwd_bytes_total;

    local flow_bytes_s = 0.0;
    local flow_pkts_s  = 0.0;
    if ( duration > 0sec )
    {
        flow_bytes_s = double(total_bytes) / duration;
        flow_pkts_s  = double(total_pkts) / duration;
    }

    # Fwd/Bwd Packets/s
    local fwd_pkts_s = 0.0;
    local bwd_pkts_s = 0.0;
    if ( duration > 0sec )
    {
        fwd_pkts_s = double(fd$fwd_pkt_count) / duration;
        bwd_pkts_s = double(fd$bwd_pkt_count) / duration;
    }

    # Packet Length Variance (overall)
    # (간단히 forward+backward lengths 합쳐서 std^2)
    local all_len = append(fd$forward_lengths, fd$backward_lengths);
    local all_stats = compute_stats(all_len);
    local pkt_len_variance = all_stats.std * all_stats.std;

    # Down/Up Ratio (임의로 total bwd bytes / total fwd bytes?)
    local down_up_ratio = 0.0;
    if ( fd$fwd_bytes_total > 0 ) 
        down_up_ratio = double(fd$bwd_bytes_total) / double(fd$fwd_bytes_total);

    # Average Packet Size
    local avg_packet_size = 0.0;
    if ( total_pkts > 0 )
        avg_packet_size = double(total_bytes) / double(total_pkts);

    # Subflow (간단히 fwd/bwd pkt/bytes)
    # In real dataset, "Subflow" is about splitted flows. We'll just replicate same counts
    local subflow_fwd_packets = fd$fwd_pkt_count;
    local subflow_fwd_bytes   = fd$fwd_bytes_total;
    local subflow_bwd_packets = fd$bwd_pkt_count;
    local subflow_bwd_bytes   = fd$bwd_bytes_total;

    # Bulk Rate etc. (실제 CIC는 TCP bulk 계수 계산, 여기선 placeholder)
    local fwd_avg_bytes_bulk = 0.0;
    local bwd_avg_bytes_bulk = 0.0;
    local fwd_avg_pkts_bulk  = 0.0;
    local bwd_avg_pkts_bulk  = 0.0;
    local fwd_avg_bulk_rate  = 0.0;
    local bwd_avg_bulk_rate  = 0.0;

    # Build JSON
    local flow_info = {
        # ---------- 식별자 ----------
        "FlowID" = fd$flow_id,
        "Source IP" = fd$source_ip,
        "Source Port" = fd$source_port,
        "Destination IP" = fd$dest_ip,
        "Destination Port" = fd$dest_port,
        "Protocol" = fmt("%s", fd$protocol),
        "Timestamp" = fmt("%.6f", fd$start_time),  # or string conversion
        # ---------- Duration ----------
        "Flow Duration" = double(duration),
        # ---------- Fwd/Bwd Packets ----------
        "Total Fwd Packets" = fd$fwd_pkt_count,
        "Total Backward Packets" = fd$bwd_pkt_count,
        # ---------- Fwd/Bwd Bytes ----------
        "Total Length of Fwd Packets" = fd$fwd_bytes_total,
        "Total Length of Bwd Packets" = fd$bwd_bytes_total,
        # ---------- Fwd Packet Length Stats ----------
        "Fwd Packet Length Max" = fwd_stats.max_v,
        "Fwd Packet Length Min" = fwd_stats.min_v,
        "Fwd Packet Length Mean" = fwd_stats.mean,
        "Fwd Packet Length Std" = fwd_stats.std,
        # ---------- Bwd Packet Length Stats ----------
        "Bwd Packet Length Max" = bwd_stats.max_v,
        "Bwd Packet Length Min" = bwd_stats.min_v,
        "Bwd Packet Length Mean" = bwd_stats.mean,
        "Bwd Packet Length Std" = bwd_stats.std,
        # ---------- Flow Bytes/s, Flow Packets/s ----------
        "Flow Bytes/s" = flow_bytes_s,
        "Flow Packets/s" = flow_pkts_s,
        # ---------- Flow IAT ----------
        "Flow IAT Mean" = double(flow_iat_stats.mean),
        "Flow IAT Std" = double(flow_iat_stats.std),
        "Flow IAT Max" = double(flow_iat_stats.max_v),
        "Flow IAT Min" = double(flow_iat_stats.min_v),
        # ---------- Fwd IAT ----------
        "Fwd IAT Total" = double( fwd_iat_stats.mean * |fd$forward_timestamps| ), # 단순 예시
        "Fwd IAT Mean" = double(fwd_iat_stats.mean),
        "Fwd IAT Std" = double(fwd_iat_stats.std),
        "Fwd IAT Max" = double(fwd_iat_stats.max_v),
        "Fwd IAT Min" = double(fwd_iat_stats.min_v),
        # ---------- Bwd IAT ----------
        "Bwd IAT Total" = double( bwd_iat_stats.mean * |fd$backward_timestamps| ), 
        "Bwd IAT Mean" = double(bwd_iat_stats.mean),
        "Bwd IAT Std" = double(bwd_iat_stats.std),
        "Bwd IAT Max" = double(bwd_iat_stats.max_v),
        "Bwd IAT Min" = double(bwd_iat_stats.min_v),
        # ---------- Flags ----------
        "Fwd PSH Flags" = fd$fwd_psh_flags,
        "Bwd PSH Flags" = fd$bwd_psh_flags,
        "Fwd URG Flags" = fd$fwd_urg_flags,
        "Bwd URG Flags" = fd$bwd_urg_flags,
        # TCP total flags
        "FIN Flag Count" = fd$fin_flag_count,
        "SYN Flag Count" = fd$syn_flag_count,
        "RST Flag Count" = fd$rst_flag_count,
        "PSH Flag Count" = fd$psh_flag_count,
        "ACK Flag Count" = fd$ack_flag_count,
        "URG Flag Count" = fd$urg_flag_count,
        "CWE Flag Count" = fd$cwe_flag_count,
        "ECE Flag Count" = fd$ece_flag_count,
        # ---------- Header Lengths ----------
        "Fwd Header Length" = fd$fwd_header_len,
        "Bwd Header Length" = fd$bwd_header_len,
        # ---------- Fwd/Bwd Packets/s ----------
        "Fwd Packets/s" = fwd_pkts_s,
        "Bwd Packets/s" = bwd_pkts_s,
        # ---------- Packet Length (전체) ----------
        "Min Packet Length" = all_stats.min_v,
        "Max Packet Length" = all_stats.max_v,
        "Packet Length Mean" = all_stats.mean,
        "Packet Length Std" = all_stats.std,
        "Packet Length Variance" = pkt_len_variance,
        # ---------- Down/Up Ratio ----------
        "Down/Up Ratio" = down_up_ratio,
        # ---------- Average Packet Size ----------
        "Average Packet Size" = avg_packet_size,
        # ---------- Avg Fwd/Bwd Segment Size (CIC 정의와 정확 일치 X) ----------
        "Avg Fwd Segment Size" = if (fd$fwd_pkt_count > 0) then double(fd$fwd_bytes_total)/double(fd$fwd_pkt_count) else 0.0,
        "Avg Bwd Segment Size" = if (fd$bwd_pkt_count > 0) then double(fd$bwd_bytes_total)/double(fd$bwd_pkt_count) else 0.0,
        # ---------- Bulk Rate (placeholder) ----------
        "Fwd Avg Bytes/Bulk" = fwd_avg_bytes_bulk,
        "Fwd Avg Packets/Bulk" = fwd_avg_pkts_bulk,
        "Fwd Avg Bulk Rate" = fwd_avg_bulk_rate,
        "Bwd Avg Bytes/Bulk" = bwd_avg_bytes_bulk,
        "Bwd Avg Packets/Bulk" = bwd_avg_pkts_bulk,
        "Bwd Avg Bulk Rate" = bwd_avg_bulk_rate,
        # ---------- Subflow ----------
        "Subflow Fwd Packets" = subflow_fwd_packets,
        "Subflow Fwd Bytes" = subflow_fwd_bytes,
        "Subflow Bwd Packets" = subflow_bwd_packets,
        "Subflow Bwd Bytes" = subflow_bwd_bytes,
        # ---------- Init_Win_bytes_forward/backward (Zeek doesn't track by default) ----------
        "Init_Win_bytes_forward" = 0, 
        "Init_Win_bytes_backward" = 0,
        "act_data_pkt_fwd" = 0,
        "min_seg_size_forward" = 0,
        # ---------- Active/Idle Stats ----------
        "Active Mean" = double(active_s.mean),
        "Active Std" = double(active_s.std),
        "Active Max" = double(active_s.max_v),
        "Active Min" = double(active_s.min_v),
        "Idle Mean" = double(idle_s.mean),
        "Idle Std" = double(idle_s.std),
        "Idle Max" = double(idle_s.max_v),
        "Idle Min" = double(idle_s.min_v)
    };

    local json_str = fmt("%s", flow_info);
    kafka_producer->send("network-traffic", key, json_str);

    # cleanup
    delete flow_table[key];
}

event zeek_done()
{
    kafka_producer->flush();
    print("Zeek Kafka Producer flushed and done");
}
