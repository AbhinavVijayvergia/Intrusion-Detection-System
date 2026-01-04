# Intrusion Detection System (IDS)

Canary is a lightweight, network-based Intrusion Detection System (IDS) written in Python.
It performs real-time packet capture, filters internal traffic, and detects anomalies
using rate-based heuristics.

## Features
- Live packet capture using PyShark
- Private network traffic filtering
- ICMP, TCP, and UDP handling
- Rate-based intrusion detection
- Local structured logging
- Remote alert reporting via API

## Architecture
Packet Capture → Filtering → Detection → Logging → API Reporting

## Requirements
- Linux (root access required)
- Python 3.9+
- tshark

## Installation
```bash
pip install -r requirements.txt
sudo apt install tshark
