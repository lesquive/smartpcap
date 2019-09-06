from flask import Flask, render_template, url_for
from flask import * 

app = Flask(__name__)



@app.route("/")
def index():
    return render_template("index.html")

@app.route('/success', methods = ['GET','POST'])  
def success():  
    if request.method == 'POST':  
        f = request.files['file']  
        f.save(f.filename)  
    return render_template("success.html")   

