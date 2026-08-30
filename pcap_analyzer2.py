# type: ignore


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
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTPRequest
from scapy.packet import Packet
import seaborn as sns
import os
import re
 
 
# Reads the pcap, cap, pcapng file
pcap_file_path = input("Please enter the path to the pcap file: ")
packets = rdpcap(pcap_file_path) # replace with a different file to analyze
 
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
 
import json
 
# Severity is derived from level at runtime — never stored or synced manually.
# Wazuh bands: 1-3 LOW, 4-6 MEDIUM, 7-9 HIGH, 10 CRITICAL
def _severity(level: int) -> str:
    if level == 10:  return 'CRITICAL'
    if level >= 7:   return 'HIGH'
    if level >= 4:   return 'MEDIUM'
    return 'LOW'
 
class AttackRuleEngine:
    _DEFAULTS = {
        'ssh_brute_force':      ('Rule 40111 / Rule 5712', 10, 'Wazuh host alert',    'T1110'),
        'ssh_user_enum':        ('Rule 5710',               5,  'Wazuh — rule 5710',   'T1592'),
        'web_recon_scan':       ('Rule 31101',              5,  'Wazuh web rule',       'T1595'),
        'directory_brute_force':('Rule 31151',              10, 'Wazuh + MITRE map',   'T1595.003'),
        'sql_injection':        ('Rule 31103',              6,  'Wazuh web attack',    'T1190'),
        'cve_scan':             ('CVE-2026-60002',          9,  'CVEs identified',     'T1595.002'),
        'arp_spoofing':         ('N/A — pcap capture',      8,  'Wireshark pcap',      'T1557.002'),
        'ids_signature':        ('ET emerging threat',      7,  'Suricata ET rule',    'T1071'),
        'port_scan':            ('Rule 31151',              10, 'Suricata + Wazuh',    'T1046'),
    }
 
    def __init__(self, rules_file: str = None):
        # unpack tuples into dicts; deep copy so mutations don't touch _DEFAULTS
        self._rules = {
            k: dict(zip(('rule', 'level', 'detection', 'mitre'), v))
            for k, v in self._DEFAULTS.items()
        }
        self._file = rules_file
        if rules_file:
            if os.path.isfile(rules_file):
                self._rules.update(json.load(open(rules_file)))
            else:
                self.save()
 
    def get(self, key: str) -> dict:
        r = dict(self._rules.get(key, {'rule': 'Unknown', 'level': 1,
                                        'detection': 'Unknown', 'mitre': 'N/A'}))
        r['severity'] = _severity(r['level'])
        return r
 
    def add(self, key: str, rule: str, level: int, detection: str, mitre: str = 'N/A'):
        self._rules[key] = {'rule': rule, 'level': level,
                             'detection': detection, 'mitre': mitre}
        if self._file: self.save()
 
    def remove(self, key: str):
        self._rules.pop(key, None)
        if self._file: self.save()
 
    def save(self):
        json.dump(self._rules, open(self._file, 'w'), indent=2)
 
    # dict-style access keeps classify_attack unchanged
    def __getitem__(self, key): return self.get(key)
 
 
# Pass rules_file='attack_rules.json' to persist/load custom rules across runs
ATTACK_RULES = AttackRuleEngine()
 
 
# function to summarize the traffic within the file
def summarize_traffic(packets):
    # headers of whats in the table
    headers = ["Protocol", "Src Port", "Dst port", "Packet Count", "First Timestamp", "Last Timestamp", 'Mean Packet Length']
    table = []
 
    # iterates through the packets
    for packet in packets:
        protocol = packet.__class__.__name__
        # packet count
        packet_count = 1
        # checks the length of the packet
        mean_packet_length = len(packet)
        src_port = ''
        dst_port = ''
 
        # checks if the packet has a source and destination port
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            # checks for src port
            src_port = packet[TCP].sport if packet.haslayer(TCP) else packet[UDP].sport
            # checks for dst port
            dst_port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport
        
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
        table.append([protocol, src_port, dst_port, packet_count, first_timestamp, last_timestamp, mean_packet_length])
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
 
    # creates a csv to store the data
    data = []
    for email_type, email_set in emails.items():
        for email in email_set:
            data.append({'Email Type': email_type, 'Email': email})
    for url in urls:
        data.append({'Email Type': 'URL', 'Email': url})
    for filename in filenames:
        data.append({'Email Type': 'Filename', 'Email': filename})
 
    # return it
    return data
 
 
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
 
    # FIX: the entire analysis block was outside the for loop (indentation
    # bug) so only the last packet was ever processed. Also fixed src_ip/
    # dst_ip extraction which used a pyshark-style getattr that never works
    # with scapy, and added benign_packets increment which was missing.
    for packet in capture:
        packet_number += 1
        statistics['total_packets'] += 1
 
        src_ip = packet[IP].src if packet.haslayer(IP) else ''
        dst_ip = packet[IP].dst if packet.haslayer(IP) else ''
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
 
        # DNS query extraction (was in statistics dict but never populated)
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            try:
                query = packet[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                statistics['dns_queries'][query] += 1
            except Exception:
                pass
 
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
 
        # FIX: benign_packets was never incremented
        if not risks:
            statistics['benign_packets'] += 1
 
        # checks for timestamp
        try:
            timestamp = datetime.fromtimestamp(float(packet.time)).strftime('%Y-%m-%d %H:%M:%S.%f')
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
 
    with open(filename, 'w', newline='', encoding='utf-8') as file:
        if isinstance(data[0], dict):
            writer = csv.DictWriter(file, fieldnames=headers)
            writer.writeheader()
            writer.writerows(data)
        else:
            writer = csv.writer(file)
            writer.writerow(headers)
            writer.writerows(data)
 
 
def detect_port_scan(packets):
    """
    Detects port scan activity by tracking how many distinct destination
    ports each source IP contacts within a rolling TIME_WINDOW_SECONDS window.
 
    When a single source IP hits SCAN_THRESHOLD or more distinct ports
    inside that window it is flagged as a scanner.
 
    Returns a list of dicts, one per detected scanner:
        {
            'src_ip':        str,
            'ports_scanned': sorted list of int,
            'scan_count':    int,
            'first_seen':    str  (formatted timestamp),
            'last_seen':     str  (formatted timestamp),
            'description':   str,
        }
    Also prints a summary table and writes results to port_scan_report.csv.
    """
    # src_ip -> { dst_port -> earliest timestamp }
    tracker = defaultdict(dict)
    # one result entry per src_ip (de-duplicated by IP)
    detected = {}
    # src_ip -> packet number where scan threshold was first crossed
    first_pkt_num = {}
 
    for pkt_num, packet in enumerate(packets, start=1):
        # only care about TCP/UDP packets with an IP layer
        if not packet.haslayer(IP):
            continue
        if not (packet.haslayer(TCP) or packet.haslayer(UDP)):
            continue
 
        src_ip   = packet[IP].src
        dst_port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport
        ts       = float(packet.time)
 
        # record this port with its timestamp
        tracker[src_ip][dst_port] = ts
 
        # drop ports that fall outside the rolling time window
        tracker[src_ip] = {
            p: t for p, t in tracker[src_ip].items()
            if ts - t <= TIME_WINDOW_SECONDS
        }
 
        # check threshold
        if len(tracker[src_ip]) >= SCAN_THRESHOLD:
            ports = sorted(tracker[src_ip].keys())
            times = list(tracker[src_ip].values())
            first = datetime.fromtimestamp(min(times)).strftime('%Y-%m-%d %H:%M:%S.%f')
            last  = datetime.fromtimestamp(max(times)).strftime('%Y-%m-%d %H:%M:%S.%f')
 
            # record the packet number only the first time threshold is crossed
            if src_ip not in first_pkt_num:
                first_pkt_num[src_ip] = pkt_num
 
            detected[src_ip] = {
                'src_ip':        src_ip,
                'ports_scanned': ports,
                'scan_count':    len(ports),
                'first_seen':    first,
                'last_seen':     last,
                'first_packet':  first_pkt_num[src_ip],
                'description':   (
                    f"Port scan: {len(ports)} distinct ports contacted "
                    f"within {TIME_WINDOW_SECONDS}s"
                ),
            }
 
    results = list(detected.values())
 
    # print summary table
    if results:
        print("\nPort Scan Detection Results:")
        table_rows = [
            [
                r['src_ip'],
                r['scan_count'],
                ', '.join(str(p) for p in r['ports_scanned'][:10])
                + (' ...' if len(r['ports_scanned']) > 10 else ''),
                r['first_seen'],
                r['last_seen'],
            ]
            for r in results
        ]
        print(tabulate(
            table_rows,
            headers=["Src IP", "Ports Hit", "Ports (first 10)", "First Seen", "Last Seen"],
            tablefmt="grid",
        ))
    else:
        print("\nNo port scans detected.")
 
    # write to CSV (ports_scanned stored as a space-separated string)
    csv_rows = [
        {
            'src_ip':        r['src_ip'],
            'scan_count':    r['scan_count'],
            'ports_scanned': ' '.join(str(p) for p in r['ports_scanned']),
            'first_seen':    r['first_seen'],
            'last_seen':     r['last_seen'],
            'description':   r['description'],
        }
        for r in results
    ]
    write_to_csv(
        'port_scan_report.csv',
        ['src_ip', 'scan_count', 'ports_scanned', 'first_seen', 'last_seen', 'description'],
        csv_rows,
    )
 
    return results
 
def classify_attack(packets):
    """
    Inspects packets for attack signatures and maps each finding to its
    corresponding Wazuh rule number, severity level, and detection method
    from the ATTACK_RULES table.
 
    Checks performed:
        - SSH brute force      : >10 SYN packets to port 22 within TIME_WINDOW_SECONDS
        - SSH user enumeration : SSH traffic with fewer SYNs (probe-level)
        - Web recon (Nikto)    : HTTP User-Agent contains 'nikto'
        - Directory brute force: >50 HTTP 404 responses or HEAD flood
        - SQL injection        : URI contains known SQLi keywords
        - CVE scan (nmap NSE)  : HTTP User-Agent contains 'Nmap Scripting Engine'
        - ARP spoofing         : same IP claimed by multiple MACs in ARP replies
        - Port scan            : reuses detect_port_scan result (SCAN_THRESHOLD ports/window)
 
    Returns a list of dicts, one per confirmed finding:
        {
            'attack':     str,   attack type key from ATTACK_RULES
            'src_ip':     str,
            'dst_ip':     str,
            'evidence':   str,   human-readable detail
            'rule':       str,
            'level':      int,
            'severity':   str,
            'detection':  str,
        }
    Also prints a summary table and writes results to attack_classification.csv.
    """
    findings = []
 
    # ── tracking structures ──────────────────────────────────────────
    # SSH: src_ip -> list of (timestamp, packet_number)
    ssh_syns        = defaultdict(list)
    ssh_seen        = defaultdict(set)
    # HTTP: counters and first packet number per src_ip
    http_404_count  = defaultdict(int)
    http_head_count = defaultdict(int)
    nikto_srcs      = {}   # src_ip -> first packet_number
    nmap_nse_srcs   = {}   # src_ip -> first packet_number
    sqli_srcs       = {}   # src_ip -> (first offending URI, packet_number)
    http_404_first  = {}   # src_ip -> first packet_number with a 404
    http_head_first = {}   # src_ip -> first packet_number with a HEAD
    # ARP: ip -> set of MACs; first packet seen per ip
    arp_ip_to_macs  = defaultdict(set)
    arp_first_pkt   = {}   # ip -> first packet_number
 
    SQLI_RE = re.compile(
        r'(?i)(union\s+select|select\s+.+from|updatexml|extractvalue'
        r'|benchmark\s*\(|sleep\s*\(|0x[0-9a-f]{4,}|or\s+1\s*=\s*1'
        r'|and\s+1\s*=\s*2|%27|%20select%20)',
        re.IGNORECASE,
    )
 
    for pkt_num, packet in enumerate(packets, start=1):
        ts = float(packet.time)
 
        # ── SSH brute force / user enum ──────────────────────────────
        if packet.haslayer(TCP) and packet.haslayer(IP):
            tcp = packet[TCP]
            ip  = packet[IP]
            if tcp.dport == 22:
                ssh_seen[ip.src].add(ip.dst)
                if tcp.flags & 0x02 and not tcp.flags & 0x10:
                    ssh_syns[ip.src].append((ts, pkt_num))
 
        # ── HTTP-based attacks ────────────────────────────────────────
        if packet.haslayer(Raw) and packet.haslayer(IP):
            src_ip = packet[IP].src
            try:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
            except Exception:
                payload = ''
 
            if re.search(r'(?i)user-agent:\s*[^\r\n]*nikto', payload):
                if src_ip not in nikto_srcs:
                    nikto_srcs[src_ip] = pkt_num
 
            if re.search(r'(?i)nmap scripting engine', payload):
                if src_ip not in nmap_nse_srcs:
                    nmap_nse_srcs[src_ip] = pkt_num
 
            if re.match(r'HTTP/\S+\s+404', payload):
                http_404_count[src_ip] += 1
                if src_ip not in http_404_first:
                    http_404_first[src_ip] = pkt_num
 
            if payload.startswith('HEAD '):
                http_head_count[src_ip] += 1
                if src_ip not in http_head_first:
                    http_head_first[src_ip] = pkt_num
 
            request_line = payload.split('\r\n')[0] if payload else ''
            if SQLI_RE.search(request_line) and src_ip not in sqli_srcs:
                sqli_srcs[src_ip] = (request_line[:120], pkt_num)
 
        # ── ARP spoofing ──────────────────────────────────────────────
        if packet.haslayer(ARP):
            arp = packet[ARP]
            if arp.op == 2:
                arp_ip_to_macs[arp.psrc].add(arp.hwsrc)
                if arp.psrc not in arp_first_pkt:
                    arp_first_pkt[arp.psrc] = pkt_num
 
    # ── Evaluate SSH brute force ─────────────────────────────────────
    for src_ip, entries in ssh_syns.items():
        entries.sort()
        for i, (t, pkt_num) in enumerate(entries):
            window = [(ts, n) for ts, n in entries[i:] if ts - t <= TIME_WINDOW_SECONDS]
            if len(window) >= SCAN_THRESHOLD:
                rule_info = ATTACK_RULES['ssh_brute_force']
                findings.append({
                    'attack':       'SSH Brute Force',
                    'src_ip':       src_ip,
                    'dst_ip':       '(port 22)',
                    'first_packet': pkt_num,
                    'evidence':     f"{len(window)} SYN packets to port 22 within {TIME_WINDOW_SECONDS}s",
                    'rule':         rule_info['rule'],
                    'level':        rule_info['level'],
                    'severity':     rule_info['severity'],
                    'detection':    rule_info['detection'],
                })
                break
        else:
            if len(entries) >= 3:
                rule_info = ATTACK_RULES['ssh_user_enum']
                findings.append({
                    'attack':       'SSH User Enumeration',
                    'src_ip':       src_ip,
                    'dst_ip':       '(port 22)',
                    'first_packet': entries[0][1],
                    'evidence':     f"{len(entries)} SSH connection attempts",
                    'rule':         rule_info['rule'],
                    'level':        rule_info['level'],
                    'severity':     rule_info['severity'],
                    'detection':    rule_info['detection'],
                })
 
    # ── Evaluate Nikto web recon ──────────────────────────────────────
    for src_ip, pkt_num in nikto_srcs.items():
        rule_info = ATTACK_RULES['web_recon_scan']
        findings.append({
            'attack':       'Web Recon Scan (Nikto)',
            'src_ip':       src_ip,
            'dst_ip':       '(HTTP)',
            'first_packet': pkt_num,
            'evidence':     'User-Agent header contains "nikto"',
            'rule':         rule_info['rule'],
            'level':        rule_info['level'],
            'severity':     rule_info['severity'],
            'detection':    rule_info['detection'],
        })
 
    # ── Evaluate directory brute force ────────────────────────────────
    for src_ip, count in http_404_count.items():
        if count > 50 or http_head_count.get(src_ip, 0) > 50:
            rule_info = ATTACK_RULES['directory_brute_force']
            first = min(http_404_first.get(src_ip, float('inf')),
                        http_head_first.get(src_ip, float('inf')))
            findings.append({
                'attack':       'Directory Brute Force (Gobuster)',
                'src_ip':       src_ip,
                'dst_ip':       '(HTTP)',
                'first_packet': int(first),
                'evidence':     f"{count} HTTP 404 responses, {http_head_count.get(src_ip, 0)} HEAD requests",
                'rule':         rule_info['rule'],
                'level':        rule_info['level'],
                'severity':     rule_info['severity'],
                'detection':    rule_info['detection'],
            })
 
    # ── Evaluate SQL injection ────────────────────────────────────────
    for src_ip, (uri, pkt_num) in sqli_srcs.items():
        rule_info = ATTACK_RULES['sql_injection']
        findings.append({
            'attack':       'SQL Injection (SQLmap)',
            'src_ip':       src_ip,
            'dst_ip':       '(HTTP)',
            'first_packet': pkt_num,
            'evidence':     f"SQLi pattern in request: {uri}",
            'rule':         rule_info['rule'],
            'level':        rule_info['level'],
            'severity':     rule_info['severity'],
            'detection':    rule_info['detection'],
        })
 
    # ── Evaluate nmap NSE / CVE scan ─────────────────────────────────
    for src_ip, pkt_num in nmap_nse_srcs.items():
        rule_info = ATTACK_RULES['cve_scan']
        findings.append({
            'attack':       'CVE Vulnerability Scan (nmap NSE)',
            'src_ip':       src_ip,
            'dst_ip':       '(HTTP)',
            'first_packet': pkt_num,
            'evidence':     'User-Agent header contains "Nmap Scripting Engine"',
            'rule':         rule_info['rule'],
            'level':        rule_info['level'],
            'severity':     rule_info['severity'],
            'detection':    rule_info['detection'],
        })
 
    # ── Evaluate ARP spoofing ─────────────────────────────────────────
    for ip_addr, macs in arp_ip_to_macs.items():
        if len(macs) > 1:
            rule_info = ATTACK_RULES['arp_spoofing']
            findings.append({
                'attack':       'ARP Spoofing / MITM',
                'src_ip':       list(macs)[0],
                'dst_ip':       ip_addr,
                'first_packet': arp_first_pkt.get(ip_addr, '?'),
                'evidence':     f"IP {ip_addr} claimed by {len(macs)} different MACs: {', '.join(macs)}",
                'rule':         rule_info['rule'],
                'level':        rule_info['level'],
                'severity':     rule_info['severity'],
                'detection':    rule_info['detection'],
            })
 
    # ── Port scan (reuse detect_port_scan result) ─────────────────────
    scan_results = detect_port_scan(packets)
    for result in scan_results:
        rule_info = ATTACK_RULES['port_scan']
        findings.append({
            'attack':       'Full Port Scan (nmap)',
            'src_ip':       result['src_ip'],
            'dst_ip':       '(all ports)',
            'first_packet': result.get('first_packet', '?'),
            'evidence':     result['description'],
            'rule':         rule_info['rule'],
            'level':        rule_info['level'],
            'severity':     rule_info['severity'],
            'detection':    rule_info['detection'],
        })
 
    # ── Print results table ───────────────────────────────────────────
    if findings:
        print("\nAttack Classification Results:")
        table_rows = [
            [
                f['attack'],
                f['src_ip'],
                f['first_packet'],
                f['severity'],
                f['level'],
                f['rule'],
                f['detection'],
                f['evidence'][:60] + ('...' if len(f['evidence']) > 60 else ''),
            ]
            for f in findings
        ]
        print(tabulate(
            table_rows,
            headers=["Attack", "Src IP", "First Pkt #", "Severity", "Level", "Rule", "Detection", "Evidence"],
            tablefmt="grid",
        ))
    else:
        print("\nNo attacks classified.")
 
    # ── Write to CSV ──────────────────────────────────────────────────
    write_to_csv(
        'attack_classification.csv',
        ['attack', 'src_ip', 'dst_ip', 'first_packet', 'severity', 'level', 'rule', 'detection', 'evidence'],
        findings,
    )
 
    return findings
 
 
 
# gets the functions to run
if __name__ == '__main__':
    packets = rdpcap(pcap_file_path) 
    headers, data = summarize_traffic(packets)
    write_to_csv("traffic_summary.csv", headers, data)
    email_data = extract_emails_and_urls(packets)
    write_to_csv("extracted_data.csv", ['Email Type', 'Email'], email_data)
    statistics = pcap_analysis(pcap_file_path) 
    headers, data = scan_ips(packets)
    write_to_csv("ip_counts.csv", headers, data) 
    plot_traffic_time(packets, interval=60)
    detect_port_scan(packets)
    classify_attack(packets)