from scapy.all import sniff, wrpcap
import pandas as pd
import os, time, threading


def clrScr():
    os.system("cls" if os.name == 'nt' else "clear")


clrScr()
name = input("Enter your file name: ")
clrScr()


def sniffPckt():
    global packets
    packets = sniff(timeout=5, promisc=True)
    print("Network sniffing done....☠️")


def sniffMsg():
    startTime = time.time()
    while time.time() - startTime < 5:
        print("Sniffing network.....🔍")
        time.sleep(2)


sniffThread = threading.Thread(target=sniffPckt)
sniffThread.start()

sniffMsg()
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
