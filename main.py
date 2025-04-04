from scapy.all import sniff, wrpcap
import pandas as pd
import os, time, threading, sys

if len(sys.argv) != 3 or sys.argv[1] != "-t":
    print("Usage: python main.py -t <time-to-sniff>")
    exit(1)
else:
    tts = int(sys.argv[2])


def clrScr():
    os.system("cls" if os.name == "nt" else "clear")


clrScr()
print(tts)
name = input("Enter your file name: ")
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

data = pd.DataFrame(packets)

data.to_csv(
    f"data/csv/{name}.csv",
)
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
        n.write(f"{src_ip, src_port, dst_ip, dst_port, protocol}\n")
