# SNS Assignment 3
## Team - 9


- Team Member 1 - Amogha A Halhalli (2021101007)
- Team Member 2 - Ishit Bansal (2021101083)
- Team Member 3 - Pranav Gupta (2021101095)

# Signature and Anomaly-based Intrusion Detection and Prevention System (NIDPS)

## Overview

The IDS is designed to monitor network traffic, detect malicious activities using both signature-based and anomaly-based methods, log detected attacks, and dynamically block threats. It provides a CLI-based management interface for easy operation.

## Features

1. **Network Traffic Monitoring**
   - Real-time packet capturing and analysis using Scapy
   - Display of packet information including timestamp, source/destination IP/port, and protocol

2. **Intrusion Detection Module**
   - **Anomaly-Based Detection**:
     - Multiple Port Scanning: Detects connections to multiple ports (6+) within 15 seconds
     - Sequential Port Scanning: Identifies systematic scanning of ports in sequential order
   - **Signature-Based Detection**:
     - OS Fingerprinting Detection: Identifies OS fingerprinting attempts through TCP flag patterns

3. **Intrusion Prevention**
   - Dynamic blocking of detected threats using iptables
   - Manual unblocking capability for previously blocked IPs
   - Complete clearing of the block list

4. **Alert and Logging System**
   - Comprehensive logging of detected intrusions in a log file (ids.log)
   - Log format: `Date Time — Intrusion Type — Attacker IP — Targeted Ports/Flags — Time Span Of Attack`

5. **Command-Line Interface (CLI)**
   - Interactive management of the NIDPS
   - Options to start/stop the system, view logs, manage blocked IPs, etc.

## Setup Instructions

### Prerequisites

The following packages are required:
- Python 3.6+
- Scapy
- ipaddress

### Installation

1. Install required packages:
   ```
   pip install scapy ipaddress
   sudo apt-get install python3-scapy
   ```

2. Clone/extract the repository:
   ```
   unzip 9_lab3.zip
   cd lab3
   ```

3. Run the IDS with root privileges (required for iptables):
   ```
   sudo python3 ./IDS.py
   ```

4. Run the Testing Script to generate Malicious nodes and simulate different attacks with root privileges (required for iptables):
   ```
   sudo python3 ./Test.py
   ```

### Usage

Once the IDS is running, you can interact with it through the CLI menu:

1. **Start/Stop IDS**: Begin monitoring network traffic for intrusions or Halt the IDS if already running
2. **View Live Traffic**: Display ongoing network activity in real-time
3. **View Intrusion Logs**: Check recorded attack details from the log file
4. **Display Blocked IPs**: Show the list of IPs currently blocked by the system
5. **Unblock an IP**: Allow a specific IP to regain access
6. **Clear Block List**: Remove all blocked IPs at once
7. **Exit**: Quit the CLI interface

### Testing

A test script is provided to simulate different types of attacks:

```
sudo python3 ./Test.py
```

This script performs the following attacks with different IP Addresses:

1. `Sequential Port Scanning`: Performs pinging of sequential ports at the same time from a given IP Address.
2. `Multiple Port Scanning`: Performs pinging of multiple random ports at the same time from a given IP Address.
1. `OS Fingerprinting`: Performs generation of 5+ different combinations of SYN, ACK, FIN packets in order to detect the details of the OS.

## Implementation Details

### Network Traffic Monitoring

The system uses Scapy's `sniff` function to capture network packets. Each packet is passed to a callback function that extracts relevant information:
- Timestamp
- Source IP and port
- Destination IP and port
- Protocol (TCP/UDP)
- TCP flags (for TCP packets)

### Intrusion Detection

#### Port Scanning Detection

1. **Multiple Port Scanning**:
   - Tracks connection attempts to different ports from the same IP
   - Flags an IP if it attempts to connect to 6+ different ports within 15 seconds

2. **Sequential Port Scanning**:
   - Detects systematic scanning of ports in sequence (e.g., 80, 81, 82, 83)
   - Uses sorted port lists to identify sequential patterns

#### OS Fingerprinting Detection

- Monitors TCP flag combinations from the same source IP
- Flags an IP if 5+ different flag combinations are observed within 20 seconds

### Intrusion Prevention

The system uses iptables to block malicious IPs:
- `iptables -A INPUT -s <IP> -j DROP`: Blocks all traffic from the attacker's IP
- `iptables -D INPUT -s <IP> -j DROP`: Unblocks a previously blocked IP

### Logging System

All detected intrusions are logged in `ids.log` with the following information:
- Date and time of detection
- Type of intrusion (Port Scanning, OS Fingerprinting)
- Attacker's IP address
- Details of the attack (targeted ports, flag combinations)
- Duration of the attack