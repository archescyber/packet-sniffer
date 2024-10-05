# Packet Sniffer

Welcome to the Packet Sniffer project! This Python script leverages the Scapy library to capture and analyze network packets in real-time. It's designed to provide insights into the traffic traversing your network, helping with monitoring and troubleshooting.

## Features

- **Real-Time Packet Capture**:
- Monitors both TCP and UDP traffic.
- **Detailed Output Displays:**
  - Source and destination IP addresses
  - Source and destination ports
  - Application names associated with ports
  - Process IDs of the applications
  - Packet size and protocol type
- **User-Friendly Interface**:
- Simple command-line interaction.

## Requirements

To run this script, you need to have Python installed along with the following libraries:

- [Scapy](https://scapy.readthedocs.io/en/latest/installation.html)
- [psutil](https://pypi.org/project/psutil/)

You can install the required packages using pip:

```
pip install scapy
```
```
pip install psutil
```
## Usage
Clone the repository:
```
git clone https://github.com/archescyber/packet-sniffer.git
```
```
cd packet-sniffer
```
Run the script:
```
python main.py
```
Press 'Enter' to start capturing packets.

To stop capturing, press Ctrl+C.

## Example Output
The script produces output similar to the following:

`[2024-10-05 14:34:47] Source: 140.82.X.X (chrome.exe:443, PID: 19700) -> Aim: 192.168.X.X (chrome.exe:56526, PID: None) | Dimension: 60 bytes | Protocol: TCP | TCP Flags: A | Window Size: 76`

`[2024-10-05 14:35:16] Source: 8.8.8.8 (chrome.exe:443, PID: 19500) -> Aim: 192.168.X.X (chrome.exe:56308, PID: None) | Dimension: 67 bytes | Protocol: UDP | Window Size: 33`
