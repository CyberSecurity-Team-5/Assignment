from scapy.all import *
a = IP()
a.src = '10.0.2.3'
a.dst = '10.0.2.7'
b = ICMP()
p = a/b
send(p)