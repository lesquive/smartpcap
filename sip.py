#!/usr/bin/python3
from scapy.all import *
from scapy.utils import *
import time

start = time.time()

pktnum = 0

pkts = rdpcap ('SIP_CALL_RTP_G711.dms')

for pkt in pkts:

    pktnum += 1

    try:
        if pkt[UDP].sport == 5060:
            sippkt = pkt[Raw].load
            new = str(sippkt)
            ahorasi = new.split("\\r\\n")

            for x in ahorasi:
                print (x)

    except:
        pass

end = time.time()

print("")
print("")
print("Total packets: {}".format(pktnum))
print("total execution time: {}".format(end - start))