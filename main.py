from scapy.all import sniff
import os

os.system("cls")

packets = sniff(timeout=10)

for i, packet in enumerate(packets):
    print(f"Packet{i}:{packet.summary()}")