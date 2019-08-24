from scapy.all import *
from scapy.utils import *
import time

start = time.time()

pktnum = 0

for pkt in PcapReader('20thousand.pcapng'):
    eth_src = pkt[Ether].src 
    eth_dst = pkt[Ether].dst
    pktnum = pktnum + 1

    print("")
    print("Packet number {}".format(pktnum))
    print("The source MAC is: {}".format(eth_src))
    print("The source MAC is: {}".format(eth_dst))

end = time.time()
print("")
print("total execution time: {}".format(end - start))
print(type(PcapReader('20thousand.pcapng')))