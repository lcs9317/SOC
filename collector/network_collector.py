from scapy.all import sniff, IP, TCP, UDP
from confluent_kafka import Producer
import json
import time
import logging
from pythonjsonlogger import jsonlogger
import socket
from datetime import datetime
import os

logger = logging.getLogger('network_collector')
logHandler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter()
logHandler.setFormatter(formatter)
logger.addHandler(logHandler)
logger.setLevel(logging.INFO)

class NetworkCollector:
    def __init__(self):
        self.producer = Producer({
            'bootstrap.servers': os.getenv('KAFKA_BOOTSTRAP_SERVERS', 'kafka:29092'),
            'client.id': socket.gethostname(),
        })
        self.topic = 'network-traffic'

    def delivery_report(self, err, msg):
        if err is not None:
            logger.error(f'메시지 전송 실패: {err}')
        else:
            logger.debug(f'메시지 전송 성공: {msg.topic()}[{msg.partition()}]')

    def process_packet(self, packet):
        try:
            if IP in packet:
                packet_info = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'src_ip': packet[IP].src,
                    'dst_ip': packet[IP].dst,
                    'protocol': packet[IP].proto,
                    'length': len(packet),
                }
                if TCP in packet:
                    packet_info.update({
                        'src_port': packet[TCP].sport,
                        'dst_port': packet[TCP].dport,
                        'flags': str(packet[TCP].flags)
                    })
                elif UDP in packet:
                    packet_info.update({
                        'src_port': packet[UDP].sport,
                        'dst_port': packet[UDP].dport
                    })

                self.producer.produce(
                    self.topic,
                    key=packet_info['src_ip'],
                    value=json.dumps(packet_info),
                    callback=self.delivery_report
                )
                self.producer.poll(0)

        except Exception as e:
            logger.error(f'패킷 처리 중 오류 발생: {e}')

    def start_capture(self, interface="eth0"):
        logger.info(f'네트워크 캡처 시작 (인터페이스: {interface})')
        try:
            sniff(
                iface=interface,
                prn=self.process_packet,
                store=0,
                # 필요하다면 특정 포트 필터링 예시:
                # filter="tcp port 80 or tcp port 443"
            )
        except Exception as e:
            logger.error(f'패킷 캡처 중 오류 발생: {e}')

if __name__ == "__main__":
    collector = NetworkCollector()
    collector.start_capture()
