import logging
from logging import DEBUG, INFO, WARNING, ERROR, CRITICAL
import argparse
from scapy.all import *
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP
from collections import Counter, defaultdict
import pyshark
import csv
import matplotlib.pyplot as plt

packets = rdpcap('pcaps/SkypeIRC.cap')

logging.basicConfig(level=INFO, format_str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s")

SCAN_THRESHOLD = 10
TIME_WINDOW_SECONDS = 5

KNOWN_MALICIOUS_PORTS = {
    23: "Telnet",
    139: "NetBIOS",
    445: "SMB",
    3389: "RDP",
    6667: "IRC",
    6668: "IRC",
    5544: "ADB"
}

WELL_KNOWN_PORTS = {
    80: "HTTP",
    443: "HTTPS",
    21: "FTP",
    22: 'SSH',
    53: 'DNS',
    25: "SMTP",
    110: "POP3",
    143: "IMAP"
}

def pcap_analysis(file_path, filter_ip=None, filter_port=None):
    capture = pyshark.FileCapture(file_path)
    statistics = {
        'total_packets': 0,
        'malicious_packets': 0,
        'benign_packets': 0,
        'protocols': Counter(),
        'ip_addresses': Counter(),
        'dns_queries': Counter(),
        'tcp_ports': Counter(),
        'udp_ports': Counter(),
        'http_requests': Counter(),
        'udp_ports': Counter(),
        'timestamps': [],
        'per_packet_analysis': [],
        'detected_anomalies': {
            'port_scans': [],
            'malicious_traffic': [],
            'unusual_port_usage': [],
            'high_connection_attempts': []
        }
    }
    port_scan_tracker = defaultdict{list}
    packet_number = 0
    while True:
        packet = capture.next_packet()
        if packet is None:
            break

        packet_number += 1
        packets[packet_number] = {
            'protocol': packet.highest_layer,
            'source_ip': '',
            'destination_ip': '',
            'dns_query': '',
            'timestamp': packet.sniff_time.strftime('%Y-%m-%d %H:%M:%S.%f'),
            'risks': []
        }

        src_ip = getattr(packet, 'ip', None) and packet.ip.src or ''
        dst_ip = getattr(packet, 'ip', None) and packet.ip.dst or ''
        src_port = ''
        dst_port = ''
        protocol = packet.highest_layer

        if hasattr(packet, 'tcp'):
            src_port = int(packet.tcp.srcport)
            dst_port = int(packet.tcp.dstport)
            statistics['tcp_ports'][src_port] += 1
        elif hasattr(packet, 'udp'):
            src_port = int(packet.udp.srcport)
            dst_port = int(packet.udp.dstport)
            statistics['udp_ports'][dst_port] += 1

        risks = []
        if dst_port in KNOWN_MALICIOUS_PORTS:
            risk_msg = f"Malicious port detected: {dst_port} ({KNOWN_MALICIOUS_PORTS[dst_port]})"
            statistics['malicious_packets'] += 1
            statistics['detected_anomalies']['malicious_traffic'].append((
                
            ))
        
    print(statistics)
    print("-------------------------------------")
    print(f"Total Packets: (statistics['total_packets'])")
    print(f"Malicious Packets: (statistics['malicious_packets'])")
    print(f"Benign Packets: (statistics['benign_packets'])")
    print(f"Protocols: (statistics['protocols'])")
    print(f"IP Addresses: (statistics['ip_addresses'])")
    print(f"DNS Queries: (statistics['dns_queries'])")
    print(f"TCP Ports: (statistics['tcp_ports'])")
    print(f"UDP Ports: (statistics['udp_ports'])")
    print(f"HTTP Requests: (statistics['http_requests'])")
    print(f"UDP Ports: (statistics['udp_ports'])")
    print(f"Timestamps: (statistics['timestamps'])")
    print(f"Per-Packet Analysis: (statistics['per_packet_analysis'])")

if __name__ == '__main__':
    pcap_analysis('pcaps/SkypeIRC.cap')