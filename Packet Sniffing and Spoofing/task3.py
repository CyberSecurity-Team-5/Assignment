#!/usr/bin/python3
from scapy.all import *

result, unans = sr(IP(dst="8.8.8.8",ttl=(1))/ICMP())

for i,rcv in result:
    print(i.ttl,rcv.src)
