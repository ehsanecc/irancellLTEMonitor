import requests
from hashlib import md5
import sqlite3
from time import sleep
import argparse
from os import system

parser = argparse.ArgumentParser("irancellLTEMonitor", description="This program runs in background and monitor for LTE signal changes, you can set threshold for modem reboot.")
parser.add_argument("--db", default="database.db", type=str)
parser.add_argument("--user", default="admin", type=str)
parser.add_argument("--pass", default="admin", type=str)
parser.add_argument("--panel", default="192.168.1.1", type=str)
parser.add_argument("--threshold", default=3, type=str, choices=[2,3,4])
parser.add_argument("--run-after-reboot", default='', type=str)
args = parser.parse_args()

dbcon = sqlite3.connect(args.db)
if not dbcon:
    print('ERROR: DB connection error')
    exit(-1)
r = dbcon.execute("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
tables = [i[0] for i in r.fetchall()]
if 'log' not in tables:
    dbcon.execute('CREATE TABLE "log" (\
        "id"	INTEGER NOT NULL UNIQUE,\
        "message"	TEXT,\
        "time"	TEXT DEFAULT CURRENT_TIMESTAMP,\
        PRIMARY KEY("id")\
    );')
if 'lte_status' not in tables:
    dbcon.execute('CREATE TABLE "lte_status" (\
        "id"	INTEGER NOT NULL UNIQUE,\
        "uicc"	TEXT,\
        "dl_speed"	INTEGER,\
        "ul_speed"	INTEGER,\
        "cell_id"	INTEGER,\
        "ecgi"	INTEGER,\
        "rssi"	INTEGER,\
        "rsrp"	INTEGER,\
        "rsrq"	REAL,\
        "sinr"	INTEGER,\
        "band"	INTEGER,\
        "earfcn"	INTEGER,\
        "bandwidth"	TEXT,\
        "txpower"	REAL,\
        "service_cell_state"	TEXT,\
        "connection"	TEXT,\
        "internet"	INTEGER,\
        "pdn_type"	TEXT,\
        "lte0pdn0_rxbytes"	INTEGER,\
        "lte0pdn0_txbytes"	INTEGER,\
        "time"	TEXT DEFAULT CURRENT_TIMESTAMP,\
        PRIMARY KEY("id" AUTOINCREMENT)\
    );')
dbcon.commit()

user = args.user
password = args['pass']

def log(message:str):
    global dbcon

    print(message, flush=True)
    dbcon.execute("INSERT INTO `log`(message) VALUES (?)", (message,))
    dbcon.commit()

def check_response(response:dict):
    return response['status'] == '0' and response['result'] == '0'

def lteSignal(rsrp):
    sigLevel = 0

    if rsrp < -115 and rsrp > -150:
        sigLevel = 1
    elif rsrp < -105 and rsrp >= -115:
        sigLevel = 2
    elif rsrp < -95 and rsrp >= -105:
        sigLevel = 3
    elif rsrp >= -95:
        sigLevel = 4

    return sigLevel

def login():
    global session, token, args
    r = session.get(f"http://{args.panel}/cgi-bin/auth.cgi?func=login&user={user}&pass={md5(password.encode('utf8')).hexdigest()}")
    if not r.ok:
        log('ERROR: ' + r.text)
        exit(-1)
    jres = r.json()
    if not check_response(jres):
        log('ERROR: cannot login')
        exit(-1)
    token = jres['token']
    session.cookies.set("auth_token", token)

def reboot():
    global session, token, args

    if check_response(session.get(f"http://{args.panel}/cgi-bin/system.cgi?func=reboot&token={token}").json()):
        log("Waiting for 30 seconds to reboot ... ")
        sleep(30)
        
    else:
        log('ERROR: rebooting error')
        exit(-1)

session = requests.Session()
login()
log("Logger is running ... ")
while True:
    r = session.get(f"http://{args.panel}/cgi-bin/lte.cgi?func=lte_status&token={token}")
    if not r.ok:
        log('ERROR: ' + r.text)
        exit(-1)
    jres = r.json()
    if not check_response(jres):
        log('ERROR: cannot login')
        exit(-1)
    dbcon.execute('INSERT INTO `lte_status`(uicc, dl_speed, ul_speed, cell_id, ecgi, rssi, rsrp, rsrq, sinr, band, earfcn, bandwidth, \
        txpower, service_cell_state, connection, internet, pdn_type, lte0pdn0_rxbytes, lte0pdn0_txbytes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', 
        (jres['uicc'], jres['dl_speed'], jres['ul_speed'], jres['cell_id'], jres['ecgi'], jres['rssi'], jres['rsrp'], jres['rsrq'], jres['sinr'], 
        jres['band'], jres['earfcn'], jres['bandwidth'], jres['txpower'], jres['service_cell_state'], jres['connection'], jres['internet'], 
        jres['pdn_type'], jres['lte0pdn0_rxbytes'], jres['lte0pdn0_txbytes']))
    dbcon.commit()
    if lteSignal(int(jres['rsrp'])) < args.threshold: # we reboot
        log(f"signal level is too low {lteSignal(int(jres['rsrp']))}, so we rebooting modem ... ")
        reboot()
        if len(args.run_after_reboot):
            system(args.run_after_reboot)
    sleep(30)
