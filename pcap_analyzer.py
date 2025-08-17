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
import matplotlib.dates as mdates
from datetime import datetime, timedelta
from tabulate import tabulate
from collections import defaultdict
from scapy.layers.dns import DNS
from scapy.layers.http import HTTPRequest
from scapy.packet import Packet
import seaborn as sns
import os


# Reads the pcap, cap, pcapng file
packets = rdpcap('pcaps/SkypeIRC.cap') # replace with a different file to analyze

# Configures logging
logging.basicConfig(level=logging.INFO, format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s")

# static variables
SCAN_THRESHOLD = 10
# scans for 5 seconds
TIME_WINDOW_SECONDS = 5

# malicious ports that are know that are being looked for
KNOWN_MALICIOUS_PORTS = {
    23: "Telnet",
    139: "NetBIOS",
    445: "SMB",
    3389: "RDP",
    6667: "IRC",
    6668: "IRC",
    6669: "IRC",
    5544: "ADB",
    389: "LDAP",
    161: "SNMP", 
    22: "SSH",
    4444: "Metasploit",
    143: "IMAP",
    110: "POP3", 
    21: 'FTP',
    53: 'DNS',
    80: "HTTP",
    25: "SMTP",
    69: "TFTP",
    3386: "MySQL"
}

# well known ports that are being looked for
WELL_KNOWN_PORTS = {
    80: "HTTP",
    443: "HTTPS",
    21: "FTP",
    22: 'SSH',
    53: 'DNS',
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    3306: "MySQL",
    990: "FTPS",
    636: "LDAPS",
    161: "SNMP", 
    443: "HTTPS"
}

# function to summarize the traffic within the file
def summarize_traffic(packets):
    # headers of whats in the table
    headers = ["Protocol", "Packet Count", "First Timestamp", "Last Timestamp", 'Mean Packet Length']
    table = []

    # iterates through the packets
    for packet in packets:
        protocol = packet.__class__.__name__
        # packet count
        packet_count = 1
        # checks the length of the packet
        mean_packet_length = len(packet)

        # checks if the packet has a timestamp
        if hasattr(packet, 'sniff_time'):
            # checks the first timestamp
            first_timestamp = packet.sniff_time.strftime('%Y-%m-%d %H:%M:%S.%f')
            last_timestamp = packet.sniff_time.strftime('%Y-%m-%d %H:%M:%S.%f')
        # if the packet doesn't have a timestamp 
        else:
            # sets the timestamp to unknown
            first_timestamp = 'Unknown'
            last_timestamp = 'Unknown'

        # adds the data to the table
        table.append([protocol, packet_count, first_timestamp, last_timestamp, mean_packet_length])
    print("\nTraffic Summary: ")
    # prints the table as a grid
    print(tabulate(table, headers=headers, tablefmt="grid"))
    return headers, table

# function to extract emails and urls
def extract_emails_and_urls(packets):
    # checks for to and from for emails
    emails = {"To": set(), "From": set()}
    # checks for urls
    urls = set()
    # checks for filenames
    filenames = set()
    # checks for image filenames
    image_extentions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'}
    
    # iterates through the packets
    for packet in packets:
        # checks if the packet is a packet
        if isinstance(packet, Packet) and packet.haslayer(scapy.layers.inet.TCP) and packet.haslayer(Raw):
            # decodes the payload for utf-8
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            # checks for emails with regex
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            # checks for pattern with to
            emails['To'].update(re.findall(email_pattern, payload))
            # checks for pattern with from
            emails['From'].update(re.findall(email_pattern, payload))
            # checks for urls with regex
            url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
            # checks for pattern
            urls.update(re.findall(url_pattern, payload))
            # checks for filenames with regex
            filename_pattern = r'\b\w+\.\w+b'
            # checks for pattern
            filenames.update(re.findall(filename_pattern, payload))

    # prints extracted emails
    print("Extracted Emails: ")
    print(emails)
    # prints extracted urls
    print("Extracted URLs: ")
    print(urls)
    # prints extracted filenames
    print("Extracted Filenames: ")
    print(filenames)
    # prints extracted image filenames
    print("Extracted Image Filenames: ")
    print(image_extentions)


# function that analyzes the pcap
def pcap_analysis(file_path, filter_ip=None, filter_port=None):
    # gets the path of the file
    capture = rdpcap(file_path)
    # iterates through the packets looking for the statistics below
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
    # scans the port
    port_scan_tracker = defaultdict(list)
    # iterates through the packets
    packet_number = 0
    for packet in packets:
        # adds for every packet
        packet_number += 1
        # prints total packet
        statistics['total_packets'] += 1

    # checks the source and destination ip
    src_ip = getattr(packet, 'ip', None) and packet.ip.src or ''
    dst_ip = getattr(packet, 'ip', None) and packet.ip.dst or ''
    # checks the source and destination port
    src_port = ''
    dst_port = ''
    protocol = packet.__class__.__name__

    # adds the source and destination ip
    if src_ip: 
        statistics['ip_addresses'][src_ip] += 1
    if dst_ip:
        statistics['ip_addresses'][dst_ip] += 1


    # if the function has tcp ports in the src and dst
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        # prints the tcp ports for src
        statistics['tcp_ports'][src_port] += 1
        # prints the tcp ports for dst
        statistics['tcp_ports'][dst_port] += 1
    
    # if the packet has UDP ports
    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        if dst_port:
            # prints the udp ports
            statistics['udp_ports'][dst_port] += 1

    # if the packet has http
    if packet.haslayer(HTTPRequest):
        # prints the http requests
        statistics['http_requests'][packet[HTTPRequest].Path] += 1
    
    # prints the timestamps
    statistics['timestamps'].append(packet.time)

    # identifies the risks
    risks = []
    # if the dst port has known malicious ports
    if dst_port in KNOWN_MALICIOUS_PORTS:
        # prints the port that is malicious
        risk_msg = f"Malicious port detected: {dst_port} ({KNOWN_MALICIOUS_PORTS[dst_port]})"
        # adds to the statistics
        statistics['malicious_packets'] += 1
        # prints the anomalies and traffic
        statistics['detected_anomalies']['malicious_traffic'].append({
            # prints the packet number
            'packet_number': packet_number,
            # prints the src ip
            'src_ip': src_ip,
            # prints the dst ip
            'dst_ip': dst_ip,
            # prints the dst port
            'port': dst_port,
            # prints the risk description
            'description': risk_msg
        })
        risks.append(risk_msg)
    # if the dst port has well known ports
    elif dst_port and dst_port not in WELL_KNOWN_PORTS:
        # prints the unusual port usage
        risk_msg = f"Unusual port usage: {dst_port}"
        # adds to the statistics
        statistics['detected_anomalies']['unusual_port_usage'].append({
            # prints the packet number and other information
            'packet_number': packet_number,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'port': dst_port,
            'description': risk_msg
        })
    # checks for timestamp
    try:
        timestamp = packet.sniff_time.strftime('%Y-%m-%d %H:%M:%S.%f')
    except (AttributeError, TypeError):
        timestamp = 'Unknown'
    # prints a per packet analysis of the file
    statistics['per_packet_analysis'].append({
        # prints the packet number through risk
        'packet_number': packet_number,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'src_port': src_port,
        'dst_port': dst_port,
        'protocol': protocol,
        'timestamp': timestamp,
        'risks': risks
    })
    # prints the statsistcs below
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


# function that scans for ip addresses
def scan_ips(packets):
    # scans the ips
    ip_counter = Counter()
    # iterates through the packets
    for pkt in packets:
        if pkt.haslayer(IP):
            # adds the ip for src
            ip_counter[pkt[IP].src] += 1
            # adds the ip for dst
            ip_counter[pkt[IP].dst] += 1
    # prints the ip addresses
    print("\nIP Address Counts: ")
    # iterates through the ip addresses
    for ip, count in ip_counter.items():
        # prints the ip count
        print(f"{ip}: {count}")
    headers = ["IP", "Count"]
    data = [(ip, count) for ip, count in ip_counter.items()]
    return headers, data

# function that plots it
def plot_traffic_time(packets, interval=60):
    if not packets:
        return
    # plots the packets
    start_time = datetime.fromtimestamp(float(packets[0].time))
    counts = Counter()

    # iterates throught the packets
    for pkt in packets:
        # checks for time
        delta = int(pkt.time - packets[0].time)
        bin_time = (delta // interval) * interval
        # counts the time
        counts[bin_time] += 1
    # gets the time
    times = [start_time + timedelta(seconds=i) for i in sorted(counts.keys())]
    # gets the counts
    packet_counts = [counts[i] for i in sorted(counts.keys())]

    sns.set()
    plt.figure(figsize=(12, 6))
    plt.plot(times, packet_counts, marker='o')
    plt.title("Packet Counts Over Time")
    plt.xlabel("Time (seconds)")
    plt.ylabel("Packet Count")
    plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d %H:%M:%S'))
    plt.gcf().autofmt_xdate()
    plt.grid(True)
    plt.show()

def write_to_csv(filename, headers, data):
    if not data:
        print("No data to write")
        return 

    with open(filename, 'w', newline='') as file:
        if isinstance(data[0], dict):
            writer = csv.DictWriter(file, fieldnames=headers)
            writer.writeheader()
            writer.writerows(data)
        else:
            writer = csv.writer(file)
            writer.writerow(headers)
            writer.writerows(data)

# gets the functions to run
if __name__ == '__main__':
    packets = rdpcap('pcaps/SkypeIRC.cap') # replace with a different file to analyze
    headers, data = summarize_traffic(packets)
    write_to_csv("traffic_summary.csv", headers, data)
    extract_emails_and_urls(packets)
    statistics = pcap_analysis('pcaps/SkypeIRC.cap') # replace with a different file to analyze
    headers, data = scan_ips(packets)
    write_to_csv("ip_counts.csv", headers, data) 
    plot_traffic_time(packets, interval=60)
    
