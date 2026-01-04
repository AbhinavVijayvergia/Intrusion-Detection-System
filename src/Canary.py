import pyshark
import netifaces
import ipaddress

intF = netifaces.gateways()['default'][netifaces.AF_INET][1]
capture = pyshark.LiveCapture(interface=intF)


def is_private_ip(ip_address:str)-> bool:
	ip = ipaddress.ip_address(ip_address)
	return ip.is_private

for packet in capture.sniff_continuously():
	print(packet)