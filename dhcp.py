#!/usr/bin/python3
from scapy.all import *
from scapy.utils import *
import time

start = time.time()

pktnum = 0

pkts = rdpcap ('test.cap')

for pkt in pkts:

    pktnum += 1

    try:
        print(hex(pkt['BOOTP'].xid))
        print(pkt['DHCP options'].options[0])
        print(pkt['DHCP options'].options[1])
        print(pkt['DHCP options'].options[2])
        print(pkt['DHCP options'].options[3])
        print(pkt['DHCP options'].options[4])
        print(pkt['DHCP options'].options[5])
        print("")


    except:
        pass

end = time.time()

print("")
print("")
print("Total packets: {}".format(pktnum))
print("total execution time: {}".format(end - start))