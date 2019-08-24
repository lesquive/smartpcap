#!/usr/bin/python3
from scapy.all import *
from scapy.utils import *
import time

start = time.time()

pktnum = 0

pkts = rdpcap ('test.pcapng')

start2 = time.time()

for pkt in pkts:
    pktnum += 1
    try:
        eth_src = pkt[Ether].src 
        eth_dst = pkt[Ether].dst
        eth_type = pkt[Ether].type
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        ip_proto = pkt[IP].proto

        print("")
        print("Packet number {}".format(pktnum))
        print("Source MAC: {}".format(eth_src))
        print("Destination MAC: {}".format(eth_dst))
        print("Ethernet type: {}".format(eth_type))
        print("Source IP: {}".format(ip_src))
        print("Destination IP: {}".format(ip_dst))
        print("Layer 4 protocol: {}".format(ip_proto))

    except:
        print("An exception occurred")

end2 = time.time()
end = time.time()
print("")
print("total analysis time: {}".format(end2 - start2))
print("total execution time: {}".format(end - start))