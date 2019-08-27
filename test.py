from scapy.all import *
from scapy.utils import *
import time
import pcappy as pcap

conf.use_pcap=True

start = time.time()

pktnum = 0

pkts = rdpcap ('test.pcapng')

start2 = time.time()

for pkt in pkts:
    pktnum += 1
    try:
        # eth_src = pkt[Ether].src 
        # eth_dst = pkt[Ether].dst
        # eth_type = pkt[Ether].type
        # ip_src = pkt[IP].src
        # ip_dst = pkt[IP].dst
        # ip_proto = pkt[IP].proto

        # print("")
        # print("Packet number {}".format(pktnum))
        # print("The source MAC is: {}".format(eth_src))
        # print("The destination MAC is: {}".format(eth_dst))
        # print("The ethernet type is: {}".format(eth_type))
        # print("The source IP is: {}".format(ip_src))
        # print("The destination IP is: {}".format(ip_dst))
        # print("The Layer 4 protocol is: {}".format(ip_proto))

        packet = Ether(pkt)
        print (packet)

    except:
        print("An exception occurred")

end2 = time.time()
end = time.time()
print("")
print("total analysis time: {}".format(end2 - start2))
print("total execution time: {}".format(end - start))