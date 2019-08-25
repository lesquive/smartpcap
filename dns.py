#!/usr/bin/python3
from scapy.all import *
from scapy.utils import *
import time

start = time.time()

pktnum = 0

pkts = rdpcap ('110kpackets.pcapng')

for pkt in pkts:

    pktnum += 1

    try:
        print(pkt[DNS]["DNS Question Record"].qname)

    except:
        pass

end = time.time()

print("")
print("")
print("Total packets: {}".format(pktnum))
print("total execution time: {}".format(end - start))