'''
This page is going to host all the DNS functions in our application.

--------------
DNS Type codes
--------------

A (1) - IPv4 address record	
Returns a 32-bit IP address, which typically maps a domain’s hostname to an IP address, but also used for DNSBLs  and storing subnet masks

AAAA (28) - IPv6 address record	
Returns a 128-bit IP address that maps a domain’s hostname to an IP address

ANY (*) - All cached records	
Returns all records of all types known to the name server

CNAME (5) - Canonical name record	
Alias of one name to another: the DNS lookup will continue by retrying the lookup with the new name

MX (15) - Mail exchange record	
Maps a domain name to a list of message transfer agents for that domain

NS (2) - Name server record	
Delegates a DNS zone to use the specified authoritative name servers

PTR (12) - Pointer record	
Pointer to a canonical name that returns the name only and is used for implementing reverse DNS lookups

SIG (24) - Signature	
Signature record

SOA (6) - Start of authority  record	
Specifies authoritative information about a DNS zone, including the primary name server, the email of the domain  administrator, the domain serial number, and several timers relating to refreshing the zone

SRV (33) - Service locator	
Generalized service location record, used for newer protocols instead of creating protocol-specific records such as MX

TXT (16) - Text record	
Carries extra data, sometimes human-readable, most of the time machine-readable such as opportunistic encryption,  DomainKeys, DNS-SD, etc.

------------------
DNS Response Codes 
------------------

 NOERROR - RCODE:0	
 DNS Query completed successfully

 FORMERR - RCODE:1	
 DNS Query Format Error

 SERVFAIL - RCODE:2	
 Server failed to complete the DNS request

 NXDOMAIN - RCODE:3	
 Domain name does not exist.  

 NOTIMP	RCODE:4	
 Function not implemented

 REFUSED - RCODE:5	
 The server refused to answer for the query

 YXDOMAIN - RCODE:6	
 Name that should not exist, does exist

 XRRSET	- RCODE:7	
 RRset that should not exist, does exist

 NOTAUTH - RCODE:8	
 Server not authoritative for the zone

 NOTZONE - RCODE:9	
 Name not in zone

'''

#!/usr/bin/python3
from scapy.all import *
from scapy.utils import *
import time

start = time.time()

pktnum = 0
dns_ID = set()
dns_Response = set()
dns_messages = []
dnsFailed = 0

pkts = rdpcap ('dnsNSN.pcapng')

for pkt in pkts:

    pktnum += 1

    try:

        dnsId = (hex(pkt['DNS'].id))

        # dns_ID.add(dnsId)

        dns = pkt['UDP'].dport
        isDNSAnswer = bool (pkt['DNS'].qr)
        dns_error = pkt['DNS'].rcode
        # dnsQuery = pkt['DNS']['DNS Question Record'].qname
        # dnsAns = pkt['DNS']['DNS Resource Record'].rrname
        # dnsAns2 = pkt['DNS']['DNS Resource Record'].rdata
        dnsQType= pkt['DNS']['DNS Question Record'].qtype
        srcIp = pkt['IP'].src
        dstIp = pkt['IP'].dst

        # print(dns)
        # print(isDNS)
        # print(pktnum)
        # print (dnsId)
        # print (dnsQType)
        # print (dnsQuery)
        # print (srcIp)
        # print (dstIp)
        #print("")

        if isDNSAnswer == False:
            dnsQuery = pkt['DNS']['DNS Question Record'].qname
            dns_ID.add(dnsId)
            dns_messages.append("DNS type {} Query: {} with ID: {}. Source IP: {}. Destination IP: {}. Packet Number: {}".format(dnsQType, dnsQuery, dnsId, srcIp, dstIp, pktnum))

        elif dns_error == 3:
            error3 = "Domain Name doesn't appear to exist"
            dns_messages.append("DNS type {} Response with ID: {} and Error: {}. Source IP: {}. Destination IP: {}. Packet Number: {}".format(dnsQType, dnsId, error3, srcIp, dstIp, pktnum))
            dnsFailed += 1
        elif dns_error == 1:
            error1 = "DNS Query Format Error"
            dns_messages.append("DNS type {} Response with ID: {} and Error: {}. Source IP: {}. Destination IP: {}. Packet Number: {}".format(dnsQType, dnsId, error1, srcIp, dstIp, pktnum))
            dnsFailed += 1
        elif dns_error != 0:
            errorNot0 = "There was an error when trying to resolve DNS"
            dns_messages.append("DNS type {} Response with ID: {} and Error: {}. Source IP: {}. Destination IP: {}. Packet Number: {}".format(dnsQType, dnsId, errorNot0, srcIp, dstIp, pktnum))
            dnsFailed += 1

        else:
            dnsAns = pkt['DNS']['DNS Resource Record'].rrname
            dnsAns2 = pkt['DNS']['DNS Resource Record'].rdata
            dns_Response.add(dnsId)
            dns_messages.append("DNS type {} Response: {} - {} with ID: {}. Source IP: {}. Destination IP: {}. Packet Number: {}".format(dnsQType, dnsAns, dnsAns2, dnsId, srcIp, dstIp, pktnum))

        for i in dns_ID:
            if dnsId in dns_ID:
                dns_Response.add(dnsId)

        #         #print ("found a match for: {}".format(dnsId))
        #         print("DNS type {} record RES with ID: {}. Source IP: {}. Destination IP: {}. Answer: {} - {}. Packet Number: {}".format(dnsQType, dnsId, srcIp, dstIp, dnsAns, dnsAns2, pktnum))
        #         dns_Response.add(dnsId)
        #         break

    except:
        pass

#print (dns_ID)

for i in dns_messages:

    print(i)

print("")

for i in dns_ID:
    if i not in dns_Response:
        dnsFailed += 1
        print("No DNS response for: {}".format(i))

print("")
print("Number of DNS queries that failed: {}".format(dnsFailed))

end = time.time()

print("")
print("Total packets: {}".format(pktnum))
print("total execution time: {}".format(end - start))