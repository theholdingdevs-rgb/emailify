# ===============================
# FILE: app.py (ADVANCED SINGLE-STANDALONE SMTP VERIFIER)
# ===============================
# Run: python app.py
# Open: http://127.0.0.1:5000

import re, time, random, string, threading
import dns.resolver, smtplib
from queue import Queue
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

# ===============================
# CONFIGURATION
# ===============================
SMTP_TIMEOUT = 8
DELAY_RANGE = (0.3, 1.2)
SAFE_MAIL_FROM = "check@localhost"
HELO_HOST = "localhost"
MAX_THREADS = 5

ROLE_ACCOUNTS = {"admin","info","support","sales","contact","abuse"}
EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$")

# ===============================
# EMBEDDED UI (HTML + CSS + JS)
# ===============================
HTML = """
<!DOCTYPE html>
<html>
<head>
<title>Enterprise SMTP Email Verifier</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;500;700&display=swap" rel="stylesheet">
<style>
body{margin:0;font-family:Inter;background:linear-gradient(135deg,#0f2027,#203a43,#2c5364);color:#fff}
header{padding:20px;font-size:22px;font-weight:700;background:rgba(0,0,0,.3)}
.container{padding:20px}
.card{background:rgba(255,255,255,.08);border-radius:12px;padding:20px;margin-bottom:20px}
input,button{padding:12px;border-radius:8px;border:none;font-size:14px}
button{background:#00e5ff;color:#000;font-weight:600;cursor:pointer}
button:hover{opacity:.9}
.progress{height:10px;background:#333;border-radius:10px;overflow:hidden}
.progress-bar{height:100%;width:0%;background:#00e5ff}
table{width:100%;border-collapse:collapse;margin-top:15px}
th,td{padding:10px;border-bottom:1px solid rgba(255,255,255,.1)}
th{text-align:left;color:#9be7ff}
.valid{color:#4cffb0}
.invalid{color:#ff6b6b}
.risky{color:#ffd166}
.stats{display:flex;gap:20px;margin-top:10px}
.stat{flex:1;background:rgba(0,0,0,.3);padding:15px;border-radius:10px;text-align:center}
</style>
</head>
<body>
<header>Enterprise Local SMTP Email Verification Engine</header>
<div class="container">
<div class="card">
<input type="file" id="file"> <button onclick="start()">Start Verification</button>
<div class="progress"><div id="bar" class="progress-bar"></div></div>
<div class="stats">
<div class="stat">Valid: <span id="v">0</span></div>
<div class="stat">Risky: <span id="r">0</span></div>
<div class="stat">Invalid: <span id="i">0</span></div>
</div>
</div>
<div class="card">
<table id="table"><tr><th>Email</th><th>Status</th><th>SMTP</th><th>Role</th><th>Risk</th></tr></table>
</div>
</div>
<script>
let total=0,done=0,v=0,r=0,i=0;
function start(){
 let f=document.getElementById('file').files[0];
 let fd=new FormData();fd.append('file',f);
 fetch('/verify',{method:'POST',body:fd}).then(r=>r.json()).then(d=>render(d));
}
function render(data){total=data.length;
 data.forEach(x=>{
 done++;
 if(x.status=='VALID')v++;
 if(x.status=='RISKY')r++;
 if(x.status=='INVALID')i++;
 document.getElementById('v').innerText=v;
 document.getElementById('r').innerText=r;
 document.getElementById('i').innerText=i;
 document.getElementById('bar').style.width=(done/total*100)+'%';
 let t=document.getElementById('table');
 let row=t.insertRow(-1);
 row.innerHTML=`<td>${x.email}</td><td class='${x.status.toLowerCase()}'>${x.status}</td><td>${x.code}</td><td>${x.role}</td><td>${x.risk}</td>`;
 });
}
</script>
</body>
</html>
"""

# ===============================
# CORE LOGIC
# ===============================
def syntax_ok(e): return EMAIL_REGEX.match(e)

def role_check(e): return e.split('@')[0].lower() in ROLE_ACCOUNTS

def mx_lookup(domain):
    try:
        return [r.exchange.to_text() for r in dns.resolver.resolve(domain,'MX')]
    except: return []

def smtp_probe(email,mx):
    try:
        s=smtplib.SMTP(mx,timeout=SMTP_TIMEOUT)
        s.helo(HELO_HOST)
        s.mail(SAFE_MAIL_FROM)
        code,_=s.rcpt(email)
        s.quit();return code
    except: return 0

def risk_score(code,role):
    score=50
    if code==250: score+=30
    if role: score-=15
    if code in [550,551,553]: score=5
    return max(0,min(100,score))

# ===============================
# WORKER SYSTEM
# ===============================
queue=Queue();results=[]

def worker():
    while not queue.empty():
        email=queue.get()
        if not syntax_ok(email):
            results.append(res(email,"INVALID","SYNTAX","NO",5));continue
        domain=email.split('@')[1]
        mxs=mx_lookup(domain)
        if not mxs:
            results.append(res(email,"INVALID","NO_MX","NO",5));continue
        role=role_check(email)
        code=smtp_probe(email,mxs[0])
        risk=risk_score(code,role)
        status="VALID" if risk>70 else "RISKY" if risk>20 else "INVALID"
        results.append(res(email,status,code,"YES" if role else "NO",risk))
        time.sleep(random.uniform(*DELAY_RANGE))
        queue.task_done()

def res(e,s,c,rk,rs): return {"email":e,"status":s,"code":c,"role":rk,"risk":rs}

# ===============================
# ROUTES
# ===============================
@app.route('/')
def index(): return render_template_string(HTML)

@app.route('/verify',methods=['POST'])
def verify():
    results.clear()
    lines=request.files['file'].read().decode().splitlines()
    for e in lines:
        if e.strip(): queue.put(e.strip())
    threads=[threading.Thread(target=worker) for _ in range(MAX_THREADS)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    return jsonify(results)

if __name__=='__main__': app.run(debug=True)
