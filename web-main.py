from flask import Flask, render_template, url_for, session
from flask import * 
from flask_session import Session
from scapy.all import *
from scapy.utils import *

dhcp = []
dns = []
icmp =[]
woho = []

app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/loading", methods = ['GET'])
def loading():
        
    return render_template("loading.html")

@app.route("/allpackets", methods = ['GET'])
def allpackets():

    rawpackets = session["pkts"] 
    session['allpackets'] = []

    for packets in rawpackets:
        session['allpackets'].append(packets.summary())

    return render_template ("allpackets.html", allpackets=session['allpackets'])

@app.route('/success', methods = ['POST'])  
def success():  

    if request.method == 'POST':  

        #ICMP Related variables:
        session['icmp_messages'] = []
        session['icmp_errors'] = []
        session['icmpFailedCount'] = 0
        
        #DHCP Related variables:
        session['dhcp_discover'] = set()
        session['dhcp_ack'] = set()
        session['dora'] = []
        session['doraFailedCount'] = 0
        session['doraFailedList'] = []
        session['ipList'] = []

        #DNS Related variables:
        session['dns_ID'] = set()
        session['dns_Response'] = set()
        session['dns_messages'] = []
        session['dnsFailed'] = 0
        session['DNSFailedList'] = []

        #HTTP Related variables:

        #SSL Related variables:

        #ARP Related variables:
        session['arp_messages'] = []

        #SIP Related variables:
        session['sip_messages'] = []
        session['sip_layer3'] = []

        #LDAP Related variables:

        f = request.files['file']  

        session["pkts"] = rdpcap (f)

        pktnum = 0

        try:
            x = str(session["pkts"])
            y = x.split()

            y1 = y[1][4:]
            y2 = y[2][4:]
            y3 = y[3][5:]
            y4 = y[4][6:-1]

            session['mylist'] = [y1, y2, y3, y4]

        except:
            print("An exception occurred")

        for pkt in session["pkts"]:

            pktnum += 1

            try:

                if pkt['ICMP']:

                    srcIp = pkt['IP'].src
                    dstIp = pkt['IP'].dst
                    icmpType = pkt['ICMP'].type
                    icmp_code = pkt['ICMP'].code

                    if icmpType == 3: 
                        type3_codes = {0:"Net Unreachable", 1:"Host Unreachable", 2:"Protocol Unreachable", 3:"Port Unreachable", 4:"Fragmentation Needed and Don't Fragment was Set", 5:"Source Route Failed", 6:"Destination Network Unknown", 7:"Destination Host Unknown", 8:"Source Host Isolated", 9:"Communication with Destination Network is Administratively Prohibited", 10:"Communication with Destination Host is Administratively Prohibited", 11:"Destination Network Unreachable for Type of Service", 12:"Destination Host Unreachable for Type of Service", 13:"Communication Administratively Prohibited", 14:"Host Precedence Violation", 15:"Precedence cutoff in effect"}
                        
                        session['icmpFailedCount'] += 1
                    
                        session['icmp_errors'].append("ICMP Type: {} with error: {}, detected from: {} to: {}, packet number: {}".format(icmpType, type3_codes[icmp_code], srcIp, dstIp, pktnum))

                    else:
                        icmp_id = (hex(pkt['ICMP'].id))
                        icmp_seq = (hex(pkt['ICMP'].seq))
                        session['icmp_messages'].append("ICMP Type: {} with code: {}, detected from: {} to: {}, with ID: {} sequence {} and packet number: {}".format(icmpType, icmp_code, srcIp, dstIp, icmp_id, icmp_seq ,pktnum))
                    
            except:
                pass

            try:

                if pkt['BOOTP'].xid:
                    dhcpId = (hex(pkt['BOOTP'].xid))
                    option1 = (pkt['DHCP options'].options[0][1])
                    srcmac = (pkt['Ether'].src)

                    if option1 == 1:
                        session['dhcp_discover'].add(dhcpId)
                        session['dora'].append("DHCP Discover detected from {}, with transaction ID: {}, packet number: {}".format(srcmac, dhcpId, pktnum))
                    elif option1 == 2:
                        session['dora'].append("DHCP Offer detected from {}, with transaction ID: {}, packet number: {}".format(srcmac, dhcpId, pktnum))                   
                    elif option1 == 3:
                        session['dora'].append("DHCP Request detected from {}, with transaction ID: {}, packet number: {}".format(srcmac, dhcpId, pktnum))
                    elif option1 == 5:
                        session['dhcp_ack'].add(dhcpId)
                        session['dora'].append("DHCP ACK detected from {}, with transaction ID: {}, packet number: {}".format(srcmac, dhcpId, pktnum)) 
                        
            except:
                pass

            try: 
                
                if pkt['DNS']:
                    dnsId = (hex(pkt['DNS'].id))
                    dns = pkt['UDP'].dport
                    isDNSAnswer = bool (pkt['DNS'].qr)
                    dns_error = pkt['DNS'].rcode
                    dnsQType= pkt['DNS']['DNS Question Record'].qtype
                    srcIp = pkt['IP'].src
                    dstIp = pkt['IP'].dst

                    if isDNSAnswer == False:
                        dnsQuery = pkt['DNS']['DNS Question Record'].qname
                        session['dns_ID'].add(dnsId)
                        session['dns_messages'].append("DNS type {} Query: {} with ID: {}. Source IP: {}. Destination IP: {}. Packet Number: {}".format(dnsQType, dnsQuery, dnsId, srcIp, dstIp, pktnum))
                    elif dns_error == 3:
                        error3 = "Domain Name doesn't appear to exist"
                        session['dns_messages'].append("DNS type {} Response with ID: {} and Error: {}. Source IP: {}. Destination IP: {}. Packet Number: {}".format(dnsQType, dnsId, error3, srcIp, dstIp, pktnum))
                        session['dnsFailed'] +=1
                    elif dns_error == 1:
                        error1 = "DNS Query Format Error"
                        session['dns_messages'].append("DNS type {} Response with ID: {} and Error: {}. Source IP: {}. Destination IP: {}. Packet Number: {}".format(dnsQType, dnsId, error1, srcIp, dstIp, pktnum))
                        session['dnsFailed'] +=1
                    elif dns_error != 0:
                        errorNot0 = "There was an error when trying to resolve DNS"
                        session['dns_messages'].append("DNS type {} Response with ID: {} and Error: {}. Source IP: {}. Destination IP: {}. Packet Number: {}".format(dnsQType, dnsId, errorNot0, srcIp, dstIp, pktnum))
                        session['dnsFailed'] +=1
                    else:
                        dnsAns = pkt['DNS']['DNS Resource Record'].rrname
                        dnsAns2 = pkt['DNS']['DNS Resource Record'].rdata
                        session['dns_Response'].add(dnsId)
                        session['dns_messages'].append("DNS type {} Response: {} - {} with ID: {}. Source IP: {}. Destination IP: {}. Packet Number: {}".format(dnsQType, dnsAns, dnsAns2, dnsId, srcIp, dstIp, pktnum))
                  
                    # for i in session['dns_ID']:
                    #     if dnsId in session['dns_ID']:
                    #         session['dns_Response'].add(dnsId)

            except:
                pass

            try:

                if ((pkt["UDP"].dport == 5060) or (pkt["UDP"].sport == 5060) or (pkt["TCP"].dport == 5060) or (pkt["TCP"].sport == 5060)) and (pkt["IP"].len > 100): 
        
                    srcIp = pkt['IP'].src
                    dstIp = pkt['IP'].dst
                    session['sip_layer3'].append("Source IP: {} Destination IP: {}".format(srcIp, dstIp))
                    raw_sip_message = str(pkt[Raw].load)
                    sip_message = raw_sip_message.split("\\r\\n")
                    session['sip_messages'].append(sip_message)

            except:
                pass

            try:

                if pkt['ARP']:
        
                    srcmac = (pkt['Ether'].src)
                    dstmac = (pkt['Ether'].dst)
                    sender_mac = (pkt['ARP'].hwsrc)
                    sender_ip = (pkt['ARP'].psrc)
                    target_mac = (pkt['ARP'].hwdst)
                    target_ip = (pkt['ARP'].pdst)
                    arp_type = (pkt['ARP'].op)

                    if arp_type == 1:
                        session['arp_messages'].append("Source MAC: {} Destination MAC: {} - Who has: {}? Tell {}".format(srcmac, dstmac, target_ip, sender_ip))
                    if arp_type == 2:
                        session['arp_messages'].append("Source MAC: {} Destination MAC: {} - {} is at {}".format(srcmac, dstmac, target_ip, target_mac))

            except:
                pass


        for i in session['dhcp_discover']:
            if i not in session['dhcp_ack']:
                session['doraFailedList'].append("DHCP ACK missing for transaction ID: {}".format(i))
                session['doraFailedCount'] +=1

        for i in session['dns_ID']:
            if i not in session['dns_Response']:
                session['DNSFailedList'].append(("DNS error found with ID: {}".format(i)))
                # session['dnsFailed'] +=1
            
    return render_template("success.html", mylist=session['mylist'], icmp_messages=session['icmp_messages'], icmp_errors=session['icmp_errors'], icmpFailedCount=session['icmpFailedCount'], dhcp=session['dora'], doraFailedList=session['doraFailedList'], doraFailedCount=session['doraFailedCount'], dns=session['dns_messages'], DNSFailedList=session['DNSFailedList'], dnsFailed=session['dnsFailed'], sip_layer3=session['sip_layer3'],sip_messages=session['sip_messages'], arp_messages=session['arp_messages'])

if __name__ == '__main__':

    app.run()