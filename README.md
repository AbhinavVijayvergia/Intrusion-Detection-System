
# Intrusion Detection System (IDS)

Canary is a lightweight, network-based Intrusion Detection System (IDS) written in Python.
It performs real-time packet capture on a local network interface, filters internal traffic,
and detects anomalous behavior using rate-based heuristics.

The system reports alerts to a local web dashboard via an HTTP API.

---

## Features
- Live packet capture using PyShark (tshark backend)
- Private network traffic filtering
- ICMP, TCP, and UDP packet handling
- Rate-based anomaly detection
- Structured local logging (JSON)
- Real-time alert reporting to a web UI

---

## Architecture
``` 

Packet Capture → Filtering → Detection → Logging → API Reporting → Web Dashboard
```

---

## Requirements
- Linux (root access required for packet capture)
- Python 3.9+
- tshark

---

## Installation

```bash
git clone https://github.com/AbhinavVijayvergia/intrusion-detection-system.git
cd canary-ids

pip install -r requirements.txt
sudo apt install tshark
````

Ensure your user has permission to capture packets:

```bash
sudo usermod -a -G wireshark $USER
```

Log out and log back in if required.

---

## Usage

### Start the web dashboard

```bash
cd server
python app.py
```

The dashboard will be available at:

```
http://<local-ip>:8080
```

### Start the IDS agent

```bash
sudo python src/ids.py
```

The IDS will begin monitoring the active network interface and reporting alerts.

---

## Detection Logic

Canary currently implements **rate-based detection**:

* Tracks packet frequency per source IP
* Triggers an alert when traffic exceeds a threshold within a time window

Alert types:

* `INFO` — observed traffic
* `ALERT` — rate threshold exceeded (`RATE_ALERT`)

---

## Example Alert

```json
{
  "time_stamp": "2026-01-04T14:51:20.564002",
  "severity": "ALERT",
  "ipsrc": "192.168.127.1",
  "ipdst": "192.168.127.128",
  "transport_layer": "TCP",
  "highest_layer": "RATE_ALERT"
}
```

---

## Project Structure

```
.
├── src/
│   └── ids.py        # IDS engine
├── server/
│   ├── app.py        # Flask API + dashboard
│   └── templates/
│       └── index.html
├── logs/
│   └── YYYY-MM-DD.log
├── requirements.txt
└── README.md
```

---

## Limitations

* Designed for local network monitoring
* Uses heuristic-based detection (not signature-based)
* Not hardened for production environments
* No persistence beyond in-memory storage
