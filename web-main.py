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

@app.route('/success', methods = ['GET','POST'])  
def success():  
    if request.method == 'POST':  
        
        #DHCP Related variables:
        # session['dhcp'] = []
        session['dhcp_discover'] = set()
        session['dhcp_ack'] = set()
        session['dora'] = []
        session['doraFailedCount'] = 0
        session['doraFailedList'] = []
        session['ipList'] = []

        #DNS Related variables:
        session['dns'] = []
        f = request.files['file']  

        session["pkts"] = rdpcap (f)

        pktnum = 0

        for pkt in session["pkts"]:

            pktnum += 1

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
                    session['dns'].append(pkt)
                    
            except:
                pass


        for i in session['dhcp_discover']:
            if i not in session['dhcp_ack']:
                session['doraFailedList'].append("DHCP ACK missing for transaction ID: {}".format(i))
                session['doraFailedCount'] +=1

    return render_template("success.html", dhcp=session['dora'], doraFailedList=session['doraFailedList'], doraFailedCount=session['doraFailedCount'], dns=session['dns'])