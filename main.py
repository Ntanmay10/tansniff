from scapy.all import sniff
import pandas as pd
import os

os.system("cls")

packets = sniff(timeout=10)

df = pd.DataFrame(packets)
df.to_csv("packets.csv", index=True)

for i, packet in enumerate(packets):
    print(f"Packet{i}:{packet.summary()}")