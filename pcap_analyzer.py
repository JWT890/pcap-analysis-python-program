from scapy.all import *

packets = rdpcap('pcaps/ipv4frags.pcap')

connections = set()

for packet in packets:
    if packet.haslayer('IP'):
        ip_layer = packet['IP']
        connections.add((ip_layer.src, 
                         ip_layer.dst, 
                         ip_layer.dport))

print(connections)
print('IP Connections Report:')
print("-----------------------")

for connection in connections:
    src_ip, dst_ip, dst_port = connection
    print(f"Source IP: {src_ip}")
    print(f"Destination IP: {dst_ip}")
    print(f"Destination Port: {dst_port}")
    print("-----------------------")
else:
    print("No malicious activity detected.")