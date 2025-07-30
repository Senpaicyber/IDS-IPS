# Network Intrusion Detection System (IDS)

A comprehensive network intrusion detection system that monitors network traffic, detects suspicious activities, and alerts administrators about potential security threats.

## Features

- **Real-time Traffic Monitoring**: Captures and analyzes network packets in real-time
- **Threat Detection**: Identifies various attack patterns including port scans, brute force attempts, DDoS, and suspicious traffic
- **Web Dashboard**: Modern web interface for monitoring network activity and security alerts
- **Customizable Rules**: Define and manage detection rules based on your environment's needs
- **IP Blacklisting**: Block malicious IP addresses automatically or manually
- **Alert Management**: View, filter, and respond to security alerts
- **Network Scanning**: Discovers devices on the network and monitors their status

## Requirements

- Python 3.8+
- Linux-based operating system (tested on Ubuntu/Debian)
- Admin/root privileges (for packet capture)
- Network interface in promiscuous mode (for full network visibility)

## Installation

1. Clone the repository:
   ```
   git clone <git-repo-url>
   cd network-ids
   ```

2. Create and activate a virtual environment:
   ```
   python -m venv .venv
   source .venv/bin/activate
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Run the system:
   ```
   python src/main.py
   ```

5. Access the web interface:
   Open your browser and go to `http://localhost:5000`

## Architecture

The system consists of several components:

- **Packet Monitor**: Captures and analyzes network packets using Scapy
- **Detection Engine**: Applies rules to identify suspicious activity
- **Alert System**: Generates and stores alerts for suspicious events
- **Web Interface**: Provides visualization and management capabilities
- **Database**: Stores alerts, packets, and configuration

## Detection Capabilities

- Port scanning detection
- Brute force login attempts
- DDoS and DoS attacks
- Known malicious IP detection
- Suspicious TCP flag combinations
- HTTP/ICMP/UDP flood detection
- Anomaly-based detection
