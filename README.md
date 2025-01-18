# Tansniff

Tansniff is a lightweight network packet sniffer built using Python and the Scapy library. It captures and analyzes network packets, allowing users to inspect and save packet data for future investigation.

## Features

- Capture live network packets and generating pcap file.
- Display packet summaries in a readable format.
- Customizable capture settings (packet count, timeout, filters, etc.).

## Installation

### Clone the repository
```bash
git clone https://github.com/Ntanmay10/tansniff.git
cd tansniff
```
### Install required dependencies
```bash
pip install -r requirements.txt
```

---

### Usage

```bash
# Run the script
python tansniff.py
```

The script will:

1. Capture a limited number of packets (10 seconds).
2. Display packet summaries in the terminal.
3. Save packets summary in CSV, TXT, and PCAP files for future investigation.

---

### Configuration
```python
# Change packet count and timeout
packets = sniff(count=20, timeout=15)
```

### Add a filter to capture specific traffic (e.g., TCP)
```python
packets = sniff(count=20, timeout=15, filter="tcp")
```


## Disclaimer

Using this tool may require administrative privileges and should be done in compliance with local laws and network policies. Always obtain proper authorization before sniffing network traffic.