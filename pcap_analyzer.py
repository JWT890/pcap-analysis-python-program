import logging
from logging import DEBUG, INFO, WARNING, ERROR, CRITICAL
import argparse
from scapy.all import *
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP
from collections import Counter
import pyshark
packets = rdpcap('pcaps/SkypeIRC.cap')

format_str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

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
        'per_packet_analysis': []
    }

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

        statistics['total_packets'] += 1
        statistics['protocols'][packet.highest_layer] = statistics['protocols'].get(packet.highest_layer, 0) + 1
        statistics['ip_addresses'][packet.ip.src] = statistics['ip_addresses'].get(packet.ip.src, 0) + 1
        statistics['ip_addresses'][packet.ip.dst] = statistics['ip_addresses'].get(packet.ip.dst, 0) + 1

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


