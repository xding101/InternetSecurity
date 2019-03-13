#!/usr/bin/python
from scapy.all import *

#a = IP()
#a.show()

def print_pkt(pkt):
	pkt.show()

#1.1Ba
pkt = sniff(filter='icmp', prn=print_pkt)
#1.1Bb
pkt = sniff(filter='tcp and (src host 10.0.2.5)', prn = print_pkt)
#1.1Bc
pkt - sniff(filter='src net 128.230.0.0/16', prn = print_pkt)

#1.2
a = IP()
a.dst = '10.0.2.4'
a.show()
b = ICMP()
p = a/b
send(p)

#1.3
a = IP()
a.dst = '10.30.29.13'
a.ttl = 1 #1,2,3,4,5,6,...
b = ICMP()
send(a/b)

#1.4
def send_pkt(pkt):
	pkt.show()
	a = IP()
	a.dst = pkt[IP].src
	a.src = pkt[IP].dst
	b = ICMP()
	send(a/b)
	print("----------------------------\n")

while 1:
	pkt = sniff(filter = 'icmp', prn = sned_pkt)

