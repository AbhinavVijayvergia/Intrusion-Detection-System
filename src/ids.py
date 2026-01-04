import pyshark
import netifaces
import ipaddress
import json
import base64
import requests
import os
from datetime import datetime
import time
from collections import defaultdict, deque

WINDOW_SIZE = 10
THRESHOLD = 50

LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

packet_window = defaultdict(deque)

class PacketEvent:
    def __init__(
        self,
        severity="INFO",
        time_stamp="",
        ipsrc="",
        ipdst="",
        srcport="",
        dstport="",
        transport_layer="",
        highest_layer=""
    ):
        self.time_stamp = time_stamp
        self.severity = severity
        self.ipsrc = ipsrc
        self.ipdst = ipdst
        self.srcport = srcport
        self.dstport = dstport
        self.transport_layer = transport_layer
        self.highest_layer = highest_layer


class APIServer:
    def __init__(self, ip: str, port: str):
        self.ip = ip
        self.port = port


server = APIServer("192.168.2.132", 8080)

intF = netifaces.gateways()["default"][netifaces.AF_INET][1]
capture = pyshark.LiveCapture(interface=intF)


def is_api_server(packet, server: APIServer) -> bool:
    if hasattr(packet, "ip"):
        return packet.ip.src == server.ip or packet.ip.dst == server.ip
    return False


def is_private_ip(ip_address: str) -> bool:
    return ipaddress.ip_address(ip_address).is_private


def log_event(message: PacketEvent):
    date = datetime.utcnow().strftime("%Y-%m-%d")
    logfile = os.path.join(LOG_DIR, f"{date}.log")
    with open(logfile, "a") as f:
        f.write(json.dumps(message.__dict__) + "\n")


def report(message: PacketEvent):
    log_event(message)
    payload = base64.b64encode(
        json.dumps(message.__dict__).encode("utf-8")
    ).decode("utf-8")
    print(payload)
    try:
        requests.get(f"http://{server.ip}:{server.port}/api/?{payload}")
    except requests.exceptions.RequestException:
        pass


def detect_rate_abuse(datagram: PacketEvent) -> bool:
    now = time.time()
    q = packet_window[datagram.ipsrc]
    q.append(now)
    while q and now - q[0] > WINDOW_SIZE:
        q.popleft()
    if not q:
        packet_window.pop(datagram.ipsrc, None)
        return False
    return len(q) > THRESHOLD


def filter_packet(packet):
    if hasattr(packet, "ipv6"):
        return
    if is_api_server(packet, server):
        return
    if hasattr(packet, "icmp") and hasattr(packet, "ip"):
        event = PacketEvent(
            time_stamp=packet.sniff_time.isoformat(),
            ipsrc=packet.ip.src,
            ipdst=packet.ip.dst,
            transport_layer="ICMP",
            highest_layer=packet.highest_layer,
            severity="INFO"
        )
        report(event)
        return
    if hasattr(packet, "transport_layer") and packet.transport_layer in ("TCP", "UDP"):

        if not hasattr(packet, "ip"):
            return
        if not (
            is_private_ip(packet.ip.src)
            and is_private_ip(packet.ip.dst)
        ):
            return
        event = PacketEvent(
            time_stamp=packet.sniff_time.isoformat(),
            ipsrc=packet.ip.src,
            ipdst=packet.ip.dst,
            transport_layer=packet.transport_layer,
            highest_layer=packet.highest_layer,
        )
        if hasattr(packet, "udp"):
            event.srcport = packet.udp.srcport
            event.dstport = packet.udp.dstport
        elif hasattr(packet, "tcp"):
            event.srcport = packet.tcp.srcport
            event.dstport = packet.tcp.dstport
        if detect_rate_abuse(event):
            event.highest_layer = "RATE_ALERT"
            event.severity = "ALERT"
            report(event)


for packet in capture.sniff_continuously():
    filter_packet(packet)
