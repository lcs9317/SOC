class DDoSDetector:
    def detect_anomaly(self, traffic_data):
        # 1. 초당 패킷 수 확인
        packets_per_second = self.calculate_pps(traffic_data)
        
        # 2. 특정 IP에서의 연결 수 확인
        connections_per_ip = self.count_connections_per_ip(traffic_data)
        
        # 3. 패킷 크기 분포 분석
        packet_size_distribution = self.analyze_packet_sizes(traffic_data)
        
        # 4. 점수 계산
        anomaly_score = self.calculate_anomaly_score(
            packets_per_second,
            connections_per_ip,
            packet_size_distribution
        )
        
        return anomaly_score