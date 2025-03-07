
import io
import pytest
import pandas as pd
from inference import data_processor


@pytest.fixture
def sample_csv_data():
    csv_data = """flow_id,source_ip,source_port,destination_ip,destination_port,protocol,timestamp,flow_duration,total_fwd_packets,total_backward_packets,total_length_of_fwd_packets,total_length_of_bwd_packets,fwd_packet_length_max,fwd_packet_length_min,fwd_packet_length_mean,fwd_packet_length_std,bwd_packet_length_max,bwd_packet_length_min,bwd_packet_length_mean,bwd_packet_length_std,flow_bytes_per_sec,flow_packets_per_sec,flow_iat_mean,flow_iat_std,flow_iat_max,flow_iat_min,fwd_iat_total,fwd_iat_mean,fwd_iat_std,fwd_iat_max,fwd_iat_min,bwd_iat_total,bwd_iat_mean,bwd_iat_std,bwd_iat_max,bwd_iat_min,fwd_psh_flags,bwd_psh_flags,fwd_urg_flags,bwd_urg_flags,fwd_header_length,bwd_header_length,fwd_packets_per_sec,bwd_packets_per_sec,min_packet_length,max_packet_length,packet_length_mean,packet_length_std,packet_length_variance,fin_flag_count,syn_flag_count,rst_flag_count,psh_flag_count,ack_flag_count,urg_flag_count,cwe_flag_count,ece_flag_count,down_up_ratio,average_packet_size,avg_fwd_segment_size,avg_bwd_segment_size,fwd_header_length2,fwd_avg_bytes_bulk,fwd_avg_packets_bulk,fwd_avg_bulk_rate,bwd_avg_bytes_bulk,bwd_avg_packets_bulk,bwd_avg_bulk_rate,subflow_fwd_packets,subflow_fwd_bytes,subflow_bwd_packets,subflow_bwd_bytes,init_win_bytes_forward,init_win_bytes_backward,act_data_pkt_fwd,min_seg_size_forward,active_mean,active_std,active_max,active_min,idle_mean,idle_std,idle_max,idle_min,label
192.168.10.5-104.16.207.165-54865-443-6,104.16.207.165,443,192.168.10.5,54865,6,"7/7/2017 3:30",3,2,0,12,0,6,6,6,0,0,0,0,0,4000000,666666.6667,3,0,3,3,3,3,0,3,3,0,0,0,0,0,0,0,0,0,40,0,666666.6667,0,6,6,6,0,0,0,0,0,0,1,0,0,0,0,9,6,0,40,0,0,0,0,0,0,2,12,0,0,33,-1,1,20,0,0,0,0,0,0,0,0,BENIGN
192.168.10.5-104.16.28.216-55054-80-6,104.16.28.216,80,192.168.10.5,55054,6,"7/7/2017 3:30",109,1,1,6,6,6,6,6,0,6,6,6,0,110091.7431,18348.62385,109,0,109,109,0,0,0,0,0,0,0,0,0,0,0,0,0,0,20,20,9174.311927,9174.311927,6,6,6,0,0,0,0,0,0,1,1,0,0,1,9,6,6,20,0,0,0,0,0,0,1,6,1,6,29,256,0,20,0,0,0,0,0,0,0,0,BENIGN
"""
    return csv_data

def test_csv_parsing(sample_csv_data):
    # CSV 데이터를 pandas DataFrame으로 읽어들임
    df = pd.read_csv(io.StringIO(sample_csv_data))
    # 컬럼 수가 올바른지 검증 (예: 헤더에 정의된 컬럼 수)
    expected_columns = 65  # 실제 컬럼 수 확인 후 수정
    assert len(df.columns) == expected_columns
    # 특정 값의 검증: 첫 행의 label이 "BENIGN"인지
    assert df.iloc[0]['label'] == "BENIGN"

def test_feature_extraction(sample_csv_data):
    # data_processor.extract_features() 함수가 있다면,
    # CSV 문자열을 입력으로 받아서 모델 학습에 필요한 피처 벡터를 반환하는지 테스트
    features = data_processor.extract_features(sample_csv_data)
    # 예를 들어, 반환된 features의 길이가 예상과 일치하는지
    expected_feature_count = 10  # 피처 엔지니어링 후 선택한 피처 개수 (예시)
    assert len(features) == expected_feature_count
    # 각 피처 값이 정상 범위 내에 있는지 간단히 체크
    for value in features:
        assert isinstance(value, (int, float))
