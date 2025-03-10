import io
import pytest
import pandas as pd
import numpy as np
from inference import extract_features

@pytest.fixture
def sample_csv_data():
    # 실제 CSV 문자열 (컬럼 이름도 코드에서 사용하는 키들과 같아야 함)
    csv_data = """flow_id,source_ip,source_port,destination_ip,destination_port,protocol,timestamp,flow_duration,total_fwd_packets,total_backward_packets,total_length_of_fwd_packets,total_length_of_bwd_packets,fwd_packet_length_max,fwd_packet_length_min,fwd_packet_length_mean,fwd_packet_length_std,bwd_packet_length_max,bwd_packet_length_min,bwd_packet_length_mean,bwd_packet_length_std,flow_bytes_per_sec,flow_packets_per_sec,flow_iat_mean,flow_iat_std,flow_iat_max,flow_iat_min,fwd_iat_total,fwd_iat_mean,fwd_iat_std,fwd_iat_max,fwd_iat_min,bwd_iat_total,bwd_iat_mean,bwd_iat_std,bwd_iat_max,bwd_iat_min,fwd_psh_flags,bwd_psh_flags,fwd_urg_flags,bwd_urg_flags,fwd_header_length,bwd_header_length,fwd_packets_per_sec,bwd_packets_per_sec,min_packet_length,max_packet_length,packet_length_mean,packet_length_std,packet_length_variance,fin_flag_count,syn_flag_count,rst_flag_count,psh_flag_count,ack_flag_count,urg_flag_count,cwe_flag_count,ece_flag_count,down_up_ratio,average_packet_size,avg_fwd_segment_size,avg_bwd_segment_size,fwd_header_length2,fwd_avg_bytes_bulk,fwd_avg_packets_bulk,fwd_avg_bulk_rate,bwd_avg_bytes_bulk,bwd_avg_packets_bulk,bwd_avg_bulk_rate,subflow_fwd_packets,subflow_fwd_bytes,subflow_bwd_packets,subflow_bwd_bytes,init_win_bytes_forward,init_win_bytes_backward,act_data_pkt_fwd,min_seg_size_forward,active_mean,active_std,active_max,active_min,idle_mean,idle_std,idle_max,idle_min,label
192.168.10.5-104.16.207.165-54865-443-6,104.16.207.165,443,192.168.10.5,54865,6,"7/7/2017 3:30",3,2,0,12,0,6,6,6,0,0,0,0,0,4000000,666666.6667,3,0,3,3,3,3,0,3,3,0,0,0,0,0,0,0,0,0,40,0,666666.6667,0,6,6,6,0,0,0,0,0,0,1,0,0,0,0,9,6,0,40,0,0,0,0,0,0,2,12,0,0,33,-1,1,20,0,0,0,0,0,0,0,0,BENIGN
192.168.10.5-104.16.28.216-55054-80-6,104.16.28.216,80,192.168.10.5,55054,6,"7/7/2017 3:30",109,1,1,6,6,6,6,6,0,6,6,6,0,110091.7431,18348.62385,109,0,109,109,0,0,0,0,0,0,0,0,0,0,0,0,0,0,20,20,9174.311927,9174.311927,6,6,6,0,0,0,0,0,0,1,1,0,0,1,9,6,6,20,0,0,0,0,0,0,1,6,1,6,29,256,0,20,0,0,0,0,0,0,0,0,BENIGN
"""
    return csv_data


def test_extract_features_from_csv(sample_csv_data):
    # 1) CSV를 DataFrame으로 로드
    df = pd.read_csv(io.StringIO(sample_csv_data))

    # 2) 첫 번째 행만 예시로 추출
    row_dict = df.iloc[0].to_dict()

    # 3) 테스트 대상 함수 호출
    arr = extract_features(row_dict, model_type="lstm")

    # 4) 반환값 검증
    assert isinstance(arr, np.ndarray)
    assert arr.shape[0] == 1  # batch 차원
    # 실제 feature 개수(예: 79개, 82개 등)에 따라 검사
    # assert arr.shape[1] == 82, "features 개수가 예측과 다릅니다!"
