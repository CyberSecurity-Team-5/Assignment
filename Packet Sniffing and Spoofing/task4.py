#!/usr/bin/python3
from scapy.all import *

def spoof_pkt(pkt):

    # Filter, return if the type is not an echo
    if pkt[ICMP].type != 8:
        return

    #Iinitalize it's local IP and ICMP
    ip = IP()
    ip.src = pkt[IP].dst
    ip.dst = pkt[IP].src
    icmp = ICMP()
    icmp.type = "echo-reply"
    icmp.code = 0
    icmp.id = pkt[ICMP].id
    icmp.seq = pkt[ICMP].seq
    send(ip/icmp)

# Sniffering, once there's a user with same local network ping/interacting with other IP address, it will jump into function spoof_pkt
pkt = sniff(filter='icmp',prn=spoof_pkt)
