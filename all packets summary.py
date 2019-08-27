#!/usr/bin/python3
from scapy.all import *
from scapy.utils import *
import time

start = time.time()

pktnum = 0

pkts = rdpcap ('110kpackets.pcapng')

for pkt in pkts:

    try:
        print(pkt[IP].src," ---> ", pkt[IP].dst)

    except:
        pass

    pktnum += 1

end = time.time()

print("")
print("")
print("Total packets: {}".format(pktnum))
print("total execution time: {}".format(end - start))