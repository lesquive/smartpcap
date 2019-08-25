#!/usr/bin/python3
from scapy.all import *
from scapy.utils import *
import time

start = time.time()

pktnum = 0

mac_src_list = set ()
mac_dst_list = set ()
ip_src_list = set ()
ip_dst_list = set ()

pkts = rdpcap ('live.pcap')

for pkt in pkts:

    pktnum += 1

    try:
        mac_src_list .add(pkt[Ether].src)
        mac_dst_list .add(pkt[Ether].dst)
        ip_src_list.add(pkt[IP].src)
        ip_dst_list.add(pkt[IP].dst)

    except:
        pass

end = time.time()

print("")
print(mac_src_list)
print(mac_dst_list)
print(ip_src_list)
print(ip_dst_list)

print("")
print("Total packets: {}".format(pktnum))
print("total execution time: {}".format(end - start))