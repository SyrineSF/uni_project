from flask import Flask, render_template, request, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
import uuid
import pandas as pnd
import sqlite3
from datetime import datetime
import ipaddress
import os
import requests

# Greynoise key
headers = {
    'Accept': 'application/json',
    'key': 'API'
    }

app = Flask(__name__)

dbname = str(uuid.uuid4())
#dbname = "test2"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///dbs/' + dbname + '.sqlite'
db = SQLAlchemy(app)

class Target(db.Model):
    __tablename__ = 'Target'
    _id = db.Column(db.String, primary_key=True)
    ip = db.Column(db.String)
    status = db.Column(db.String)

    def __init__(self,_id,ip,status):
        self.ip = ip
        self._id = _id
        self.status = status


db.create_all()

@app.route('/')
def index():
    conn = sqlite3.connect("dbs/" + dbname + ".sqlite", isolation_level=None, detect_types=sqlite3.PARSE_COLNAMES)
    db_df = pnd.read_sql_query("SELECT * FROM Target", conn)
    db_df.drop_duplicates(subset="ip", keep='last', inplace=True)
    db_df.to_csv('targets.csv', index=False)
    listTargets = Target.query.all()
    n = len(listTargets)
    return render_template('index.html', Targets=listTargets, rows=n)

@app.route('/addTarget', methods=['GET', 'POST'])
def addTarget():
    # _id,TargetId,TargetRequester,TargetTitle,TargetClosed
    if request.method == 'POST':
        _id = str(uuid.uuid4())
        ip = request.form.get('ip')

        if ip:
            status = "Public" if ipaddress.ip_address(ip).is_private == False else "Private"
            p = Target(_id,ip,status)
            db.session.add(p)
            db.session.commit()
    return redirect(url_for('flushTarget'))


@app.route('/updateTarget/<string:id>', methods=['GET', 'POST'])
def updateTarget(id):
    heatID = Target.query.filter_by(_id=id).first()
    if request.method == 'POST':
        _id = str(uuid.uuid4())
        TargetId = request.form.get('TargetId')
        TargetRequester =request.form.get('TargetRequester')
        TargetTitle = request.form.get('TargetTitle')
        TargetClosed = request.form.get('TargetClosed')

        if TargetId:
            heatID.TargetId = TargetId
            heatID.TargetRequester = TargetRequester
            heatID.TargetTitle = TargetTitle
            heatID.TargetClosed = TargetClosed
            db.session.commit()
            return redirect(url_for('flushTarget'))

    return render_template('heat-update.html', Products=heatID)


@app.route('/deleteTarget/<string:id>')
def deleteTarget(id):
    t = Target.query.filter_by(_id=id).first()
    db.session.delete(t)
    db.session.commit()
    return redirect(url_for('flushTarget'))


@app.route('/flushTarget')
def flushTarget():
    conn = sqlite3.connect("dbs/" + dbname + ".sqlite", isolation_level=None, detect_types=sqlite3.PARSE_COLNAMES)
    db_df = pnd.read_sql_query("SELECT * FROM Target", conn)
    db_df.drop_duplicates(subset="ip", keep='last', inplace=True)
    db_df.to_csv('targets.csv', index=False)
    return redirect(url_for('index'))


# read clean ip with no duplicate and get results from AbuseIPDB script
@app.route("/abuseIpScan")
def abuseIpScan():
    df = pnd.read_csv("targets.csv")
    df[['ip']].to_csv('hosts.txt',index=False,header=False)
    os.system("python3 scripts/AbuseIPDB.py -f hosts.txt -x -j results/ipabuse-results.json")
    resultsx = pnd.read_json("results/ipabuse-results.json").values.tolist()
    return render_template("abuseip.html",results=resultsx)


@app.route("/greynoise/<string:ip>")
def greynoise(ip):
    r = requests.get('https://api.greynoise.io/v2/experimental/gnql', params={'query': '{}'.format(ip)}, headers = headers)
    data = r.json()
    #print(data)
    #data = {'complete': True, 'count': 1, 'data': [{'ip': '195.3.146.114', 'seen': True, 'classification': 'unknown', 'spoofable': True, 'first_seen': '2019-10-16', 'last_seen': '2020-04-06', 'actor': 'unknown', 'tags': ['IPSec VPN Scanner', 'Web Scanner'], 'cve': [], 'metadata': {'country': 'Latvia', 'country_code': 'LV', 'city': 'Riga', 'organization': 'RN Data SIA', 'rdns': '', 'asn': 'AS41390', 'tor': False, 'os': 'unknown', 'category': 'business'}, 'raw_data': {'scan': [{'port': 443, 'protocol': 'TCP'}, {'port': 1723, 'protocol': 'TCP'}], 'web': {}, 'ja3': []}}], 'message': 'ok', 'query': '195.3.146.114'}

    try:
        cve = data["data"][0]["cve"]
    except:
        cve= ""

    try:
        tags = data["data"][0]["tags"]
    except:
        tags=""

    try:
        metadata = data["data"][0]["metadata"]
    except:    
        metadata=""

    try:
        webpaths = data["data"][0]["raw_data"]["web"]["paths"]
    except:
        webpaths = ""

    try:
        webUserAgent = data["data"][0]["raw_data"]["web"]["useragents"]
    except:
        webUserAgent =""
    try:
        portScan = data["data"][0]["raw_data"]["scan"]
    except:
        portScan =""
    return render_template("greynoise.html",ip=ip,cve=cve,tags=tags,metadata=metadata,webpaths=webpaths,webUserAgent=webUserAgent,portScan=portScan)




# ip.txt file --> Sqlite DB
def SqlIp():
    df = pnd.read_csv("ip.txt",header=None)
    df.drop_duplicates(keep='last', inplace=True)
    targets = df[0].values.tolist()
    print(ipaddress.ip_address('192.168.0.1').is_private)

    for ip in targets:
        status = "Public" if ipaddress.ip_address(ip).is_private == False else "Private"
        if status == "Public":    
            p = Target(str(uuid.uuid4()),ip,status)
            db.session.add(p)
            db.session.commit()

if __name__ == '__main__':
    SqlIp()
    app.run(debug=True)
