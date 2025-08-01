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
from tabulate import tabulate
from collections import defaultdict

packets = rdpcap('pcaps/SkypeIRC.cap')

logging.basicConfig(level=logging.INFO, format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s")

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

def summarize_traffic(packets):
    headers = ["Protocol", "Packet Count", "First Timestamp", "Last Timestamp", 'Mean Packet Length']
    print("\nTraffic Summary: ")
    print(tabulate(table, headers=headers, tablefmt="grid"))
    table = []

    for packet in packets:
        protocol = packet.__class__.__name__
        packet_count = 1
        first_timestamp = packet.sniff_time.strftime('%Y-%m-%d %H:%M:%S.%f')
        last_timestamp = packet.sniff_time.strftime('%Y-%m-%d %H:%M:%S.%f')
        mean_packet_length = len(packet)

        table.append([protocol, packet_count, first_timestamp, last_timestamp, mean_packet_length])
    print("\nTraffic Summary: ")
    print(tabulate(table, headers=headers, tablefmt="grid"))

def extract_emails_and_urls(packets):
    emails = {"To": set(), "From": set()}
    urls = set()
    filenames = set()
    image_extentions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'}

def pcap_analysis(file_path, filter_ip=None, filter_port=None):
    capture = rdpcap(file_path)
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
    port_scan_tracker = defaultdict(list)
    packet_number = 0
    for packet in packets:
        packet_number += 1
        statistics['total_packets'] += 1

    src_ip = getattr(packet, 'ip', None) and packet.ip.src or ''
    dst_ip = getattr(packet, 'ip', None) and packet.ip.dst or ''
    src_port = ''
    dst_port = ''
    protocol = packet.__class__.__name__

    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        statistics['tcp_ports'][src_port] += 1
        statistics['tcp_ports'][dst_port] += 1
    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        if dst_port:
            statistics['udp_ports'][dst_port] += 1

    risks = []
    if dst_port in KNOWN_MALICIOUS_PORTS:
        risk_msg = f"Malicious port detected: {dst_port} ({KNOWN_MALICIOUS_PORTS[dst_port]})"
        statistics['malicious_packets'] += 1
        statistics['detected_anomalies']['malicious_traffic'].append({
            'packet_number': packet_number,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'port': dst_port,
            'description': risk_msg
        })
        risks.append(risk_msg)
    elif dst_port and dst_port not in WELL_KNOWN_PORTS:
        risk_msg = f"Unusual port usage: {dst_port}"
        statistics['detected_anomalies']['unusual_port_usage'].append({
            'packet_number': packet_number,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'port': dst_port,
            'description': risk_msg
        })
    try:
        timestamp = packet.sniff_time.strftime('%Y-%m-%d %H:%M:%S.%f')
    except (AttributeError, TypeError):
        timestamp = 'Unknown'
    statistics['per_packet_analysis'].append({
        'packet_number': packet_number,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'src_port': src_port,
        'dst_port': dst_port,
        'protocol': protocol,
        'timestamp': timestamp,
        'risks': risks
    })
        
    print(statistics)
    print("-------------------------------------")
    print(f"Total Packets: {statistics['total_packets']}")
    print(f"Malicious Packets: {statistics['malicious_packets']}")
    print(f"Benign Packets: {statistics['benign_packets']}")
    print(f"Protocols: {statistics['protocols']}")
    print(f"IP Addresses: {statistics['ip_addresses']}")
    print(f"DNS Queries: {statistics['dns_queries']}")
    print(f"TCP Ports: {statistics['tcp_ports']}")
    print(f"UDP Ports: {statistics['udp_ports']}")
    print(f"HTTP Requests: {statistics['http_requests']}")
    print(f"Timestamps: {statistics['timestamps']}")
    print(f"Per-Packet Analysis: {statistics['per_packet_analysis']}")

if __name__ == '__main__':
    pcap_analysis('pcaps\SkypeIRC.cap', filter_ip=None, filter_port=None)