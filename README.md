# 🚀 Tansniff - Network Packet Sniffer

Tansniff is an easy-to-use tool that captures network traffic. It helps you see what data is being sent and received over your network.

## 📥 How to Install

1. **Download Tansniff**
   ```bash
   git clone https://github.com/Ntanmay10/tansniff.git
   cd tansniff
   ```
2. **Install the required software**
   ```bash
   pip install -r requirements.txt
   ```

## 🛠️ How to Use

To start sniffing network packets, run the following command:
```bash
python tansniff.py -t <time-in-seconds>
```
For example, to capture packets for 10 seconds:
```bash
python tansniff.py -t 10
```

## 📂 What You'll Get

After running the tool, Tansniff will create these files:

- 📁 **PCAP file** (`data/pcap/<filename>.pcap`) - A file you can open in Wireshark for in-depth analysis.
- 📁 **CSV file** (`data/csv/<filename>.csv`) - A table with captured packet details.
- 📁 **TXT file** (`data/txt/<filename>.txt`) - A simple text file showing key network details like IP addresses and protocols.

## ⚠️ Important Information

- 🔴 You may need **admin permissions** to run this tool.
- 🔴 Make sure you follow **local laws and network policies** before using Tansniff.
- 🔴 Only use this tool **on networks you have permission to monitor**.

🚀 **Enjoy exploring your network!** 🎉
