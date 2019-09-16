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
        session['dhcp'] = []
        f = request.files['file']  

        session["pkts"] = rdpcap (f)

        for pkt in session["pkts"]:

            try:
                # session['dhcp-confirm'] = session['dhcp'].append(hex(pkt['BOOTP'].xid))
                session['dhcp-confirm'] = pkt['BOOTP'].xid

                if session['dhcp-confirm']:
                    session['dhcp'].append(pkt)
                    

            except:
                pass

    return render_template("success.html", packets=session['dhcp'])