import csv
from pyfiglet import Figlet
from datetime import datetime
import os, time, threading, sys
from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP

os.makedirs("data/pcap", exist_ok=True)
os.makedirs("data/txt", exist_ok=True)
os.makedirs("data/csv", exist_ok=True)


def clrScr():
    os.system("cls" if os.name == "nt" else "clear")

clrScr()
fig = Figlet(font='slant')
print(fig.renderText('tansniff'))
print("\t\t\t\t--by chikoo")

if len(sys.argv) != 3 or sys.argv[1] != "-t":
    print("Usage: python main.py -t <time-to-sniff>")
    exit(1)
else:
    tts = int(sys.argv[2])

# clrScr()
name = input("Enter your file name: ")
if not name:
    name = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
clrScr()


def sniffPckt(tts):
    global packets
    packets = sniff(timeout=tts, promisc=True)
    print("Network sniffing done....☠️")


def sniffMsg(tts):
    startTime = time.time()
    while time.time() - startTime < tts:
        print("Sniffing network.....🔍")
        time.sleep(2)


sniffThread = threading.Thread(target=sniffPckt, args=(tts,))
sniffThread.start()

sniffMsg(tts)
sniffThread.join()

wrpcap(f"data/pcap/{name}.pcap", packets)

with open(f"data/csv/{name}.csv", mode="w", newline="") as file:
    writer = csv.writer(file)
    # Write header
    writer.writerow(
        ["Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Timestamp"]
    )
    for pkt in packets:
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            proto = "OTHER"
            src_port = ""
            dst_port = ""

            if TCP in pkt:
                proto = "TCP"
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
            elif UDP in pkt:
                proto = "UDP"
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
            elif ICMP in pkt:
                proto = "ICMP"

            timestamp = datetime.fromtimestamp(float(pkt.time))

            writer.writerow([src_ip, src_port, dst_ip, dst_port, proto, timestamp])

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
    with open(f"data/txt/{name}.txt", "a") as n:
        n.write(f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} | {protocol}\n")
