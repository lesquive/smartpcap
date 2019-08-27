'''
This page is going to host all the DHCP functions in our application.

1 = DHCP Discover message (DHCPDiscover).
2 = DHCP Offer message (DHCPOffer).
3 = DHCP Request message (DHCPRequest).
4 = DHCP Decline message (DHCPDecline).
5 = DHCP Acknowledgment message (DHCPAck).
6 = DHCP Negative Acknowledgment message (DHCPNak).
7 = DHCP Release message (DHCPRelease).
8 = DHCP Informational message (DHCPInform).

'''

#!/usr/bin/python3
from scapy.all import *
from scapy.utils import *
import time

start = time.time()

pktnum = 0

pkts = rdpcap ('test.cap')

dhcp_discover = set()
dora = []
doraFailed = []

for pkt in pkts:

    pktnum += 1

    try:
        # print(hex(pkt['BOOTP'].xid)) #Transaction ID
        # print(pkt['DHCP options'].options[0]) #Message type
        # print(pkt['DHCP options'].options[1]) #Client ID or Server ID
        # print(pkt['DHCP options'].options[2]) #Hostname or Lease Time
        # print(pkt['DHCP options'].options[3]) #Vendor Class ID or FQDN or SubnetMask or 
        # print(pkt['DHCP options'].options[4]) #Default Router or Client FQDN or Vendor Class ID
        # print(pkt['DHCP options'].options[5]) #Name Server or Requested Address
        # print(pkt['Ether'].src) #Source MAC Address
        # print("")

        dhcpId = (hex(pkt['BOOTP'].xid))
        option1 = (pkt['DHCP options'].options[0][1])
        option2 = (pkt['DHCP options'].options[1])
        option3 = (pkt['DHCP options'].options[2])
        option4 = (pkt['DHCP options'].options[3])
        option5 = (pkt['DHCP options'].options[4])
        option6 = (pkt['DHCP options'].options[5])
        srcmac = (pkt['Ether'].src)
        print("")

        if option1 == 1:
            dhcp_discover.add(dhcpId)
            dora.append ("DHCP Discover detected from {}, with transaction ID: {}, packet number: {}".format(srcmac, dhcpId, pktnum))
            # print ("Found the Discover!")
            # print (pktnum)
        for i in dhcp_discover:
            if option1 == 2 and dhcpId in dhcp_discover:
                dora.append("DHCP Offer detected from {}, with transaction ID: {}, packet number: {}".format(srcmac, dhcpId, pktnum))
                # print ("Found the Offer!")
                # print (pktnum)
            elif option1 == 3 and dhcpId in dhcp_discover:
                dora.append ("DHCP Request detected from {}, with transaction ID: {}, packet number: {}".format(srcmac, dhcpId, pktnum))
                # print ("Found the ACK!")
                # print (pktnum)
            elif option1 == 5 and dhcpId in dhcp_discover:
                dora.append ("DHCP ACK detected from {}, with transaction ID: {}, packet number: {}".format(srcmac, dhcpId, pktnum))
                # print ("Found the ACK!")
                # print (pktnum)
            elif option1 != 5 and option1 != 1 and dhcpId in dhcp_discover:
                doraFailed.append("DHCP ACK missing for transaction ID: {}".format(dhcpId))
                #If not Discover and not ACK to avoid False Positives, because 
                #otherwise Discover Messages will trigger.
                
    except:
        pass

for i in dora:
    print(i)

print("")
for i in doraFailed:
    print(i)

print("")
print("Number of DHCP Transactions Failed: {}".format(len(doraFailed)))

end = time.time()

print("")
print("Total packets: {}".format(pktnum))
print("total execution time: {}".format(end - start))