from scapy.all import sniff, wrpcap
from datetime import datetime
import pandas as pd
import os

os.system("cls")

packets = sniff(timeout=10)

wrpcap("network.pcap", packets)

data = pd.DataFrame(packets)
time = datetime.now().strftime("%d_%m_%y-%H_%M_%S")

data.to_csv(f"network_report_{time}.csv")

for i, packet in enumerate(packets):
    print(f"Packet{i}:{packet.summary()}")
    src_ip = packet["IP"].src if packet.haslayer("IP") else "N/A"
    dst_ip = packet["IP"].dst if packet.haslayer("IP") else "N/A"
    src_port = packet["TCP"].sport if packet.haslayer("TCP") else "N/A"
    dst_port = packet["TCP"].dport if packet.haslayer("TCP") else "N/A"
    protocol = (
        "TCP"
        if packet.haslayer("TCP")
        else "UDP" if packet.haslayer("UDP") else "Other"
    )
    with open(f"network_report_{time}.txt", "a") as n:
        n.write(f"{src_ip, src_port, dst_ip, dst_port, protocol}\n")