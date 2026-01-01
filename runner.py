# ===============================
# FILE: app.py
# SUPER-POWERFUL LOCAL SMTP EMAIL VERIFIER (STABLE + PROGRESS)
# ===============================
# This is a SINGLE-FILE, WORKING, LOCALHOST tool.
# Features:
# - Real DNS (A + MX)
# - Prefix / role detection
# - Disposable domain filtering (basic)
# - SMTP RCPT probing with smart fallbacks
# - Catch‑all detection (safe heuristic)
# - Risk scoring
# - LIVE progress bar (Server‑Sent Events)
# - Verifies one‑by‑one (visible progress)
# - FAST but rate‑limited
#
# RUN:
#   pip install flask dnspython
#   python app.py
# OPEN:
#   http://127.0.0.1:5000
# ===============================

import re
import time
import json
import random
import queue
import threading
import dns.resolver
import smtplib
import socket
from flask import Flask, request, Response, render_template_string, jsonify

# ===============================
# APP
# ===============================
app = Flask(__name__)

# ===============================
# GLOBAL STATE (SAFE FOR LOCAL TOOL)
# ===============================
TASK_QUEUE = queue.Queue()
RESULTS = []
PROGRESS = {"total": 0, "done": 0}
RUNNING = False

# ===============================
# CONFIG
# ===============================
SMTP_TIMEOUT = 10
DELAY_MIN = 0.2
DELAY_MAX = 0.6
HELO_HOST = "localhost"
MAIL_FROM = "verify@localhost"

EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$")

ROLE_PREFIXES = {
    "admin","info","support","sales","contact","help","career",
    "billing","accounts","abuse","postmaster","hr"
}

DISPOSABLE_DOMAINS = {
    "mailinator.com","tempmail.com","10minutemail.com","guerrillamail.com"
}

# ===============================
# UI (ADVANCED DASHBOARD)
# ===============================
HTML = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Enterprise SMTP Email Verifier</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
<style>
body{margin:0;font-family:Inter;background:#020617;color:#e5e7eb}
header{padding:20px;font-size:22px;font-weight:800;background:#020617;border-bottom:1px solid #1f2937}
.container{padding:20px}
.card{background:#020617;border:1px solid #1f2937;border-radius:14px;padding:20px;margin-bottom:20px}
button{padding:12px 16px;border:none;border-radius:10px;background:#22d3ee;color:#000;font-weight:700;cursor:pointer}
input{padding:12px;background:#020617;color:#fff;border:1px solid #1f2937;border-radius:10px}
.progress{height:12px;background:#1f2937;border-radius:20px;overflow:hidden;margin-top:15px}
.progress-bar{height:100%;width:0%;background:#22d3ee}
.stats{display:flex;gap:15px;margin-top:15px}
.stat{flex:1;padding:15px;border-radius:12px;background:#020617;border:1px solid #1f2937;text-align:center}
table{width:100%;border-collapse:collapse;margin-top:20px}
th,td{padding:10px;border-bottom:1px solid #1f2937;font-size:13px}
th{text-align:left;color:#67e8f9}
.valid{color:#22c55e}
.invalid{color:#ef4444}
.risky{color:#facc15}
</style>
</head>
<body>
<header>Enterprise Local SMTP Email Verification Engine</header>
<div class="container">
<div class="card">
<input type="file" id="file">
<button onclick="start()">Start Verification</button>
<div class="progress"><div id="bar" class="progress-bar"></div></div>
<div class="stats">
<div class="stat">VALID<br><span id="v">0</span></div>
<div class="stat">RISKY<br><span id="r">0</span></div>
<div class="stat">INVALID<br><span id="i">0</span></div>
</div>
</div>
<div class="card">
<table id="table">
<tr><th>Email</th><th>Status</th><th>DNS</th><th>SMTP</th><th>Role</th><th>Catch‑All</th><th>Risk</th></tr>
</table>
</div>
</div>
<script>
let v=0,r=0,i=0;
function start(){
  let f=document.getElementById('file').files[0];
  if(!f){alert('Upload file');return;}
  let fd=new FormData();fd.append('file',f);
  fetch('/start',{method:'POST',body:fd});
  listen();
}
function listen(){
  const evt=new EventSource('/stream');
  evt.onmessage=function(e){
    let d=JSON.parse(e.data);
    if(d.type==='progress'){
      document.getElementById('bar').style.width=(d.done/d.total*100)+'%';
    }
    if(d.type==='result'){
      if(d.status==='VALID')v++;
      if(d.status==='RISKY')r++;
      if(d.status==='INVALID')i++;
      document.getElementById('v').innerText=v;
      document.getElementById('r').innerText=r;
      document.getElementById('i').innerText=i;
      let row=document.getElementById('table').insertRow(-1);
      row.innerHTML=`<td>${d.email}</td><td class='${d.status.toLowerCase()}'>${d.status}</td><td>${d.dns}</td><td>${d.smtp}</td><td>${d.role}</td><td>${d.catchall}</td><td>${d.risk}</td>`;
    }
  }
}
</script>
</body>
</html>
"""

# ===============================
# UTILITIES
# ===============================

def syntax_ok(email):
    return EMAIL_REGEX.match(email) is not None


def prefix_check(email):
    return email.split('@')[0].lower() in ROLE_PREFIXES


def dns_check(domain):
    try:
        dns.resolver.resolve(domain, 'A')
        mx = dns.resolver.resolve(domain, 'MX')
        return True, sorted([r.exchange.to_text() for r in mx])
    except:
        return False, []


def smtp_probe(mx, email):
    try:
        s = smtplib.SMTP(mx, timeout=SMTP_TIMEOUT)
        s.helo(HELO_HOST)
        s.mail(MAIL_FROM)
        code, _ = s.rcpt(email)
        s.quit()
        return code
    except:
        return None


def catchall_check(mx, domain):
    fake = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(12)) + '@' + domain
    code = smtp_probe(mx, fake)
    return code == 250


def risk_engine(dns_ok, smtp_code, role, catchall, disposable):
    score = 50
    if dns_ok: score += 15
    if smtp_code == 250: score += 25
    if role: score -= 10
    if catchall: score -= 10
    if disposable: score = 5
    if smtp_code in [550,551,553]: score = 0
    return max(0, min(100, score))

# ===============================
# WORKER THREAD
# ===============================

def worker():
    global RUNNING
    while RUNNING:
        try:
            email = TASK_QUEUE.get(timeout=1)
        except:
            continue

        domain = email.split('@')[1]
        dns_ok, mxs = dns_check(domain)
        smtp_code = None
        catchall = False

        if dns_ok and mxs:
            smtp_code = smtp_probe(mxs[0], email)
            catchall = catchall_check(mxs[0], domain)

        role = prefix_check(email)
        disposable = domain in DISPOSABLE_DOMAINS
        risk = risk_engine(dns_ok, smtp_code, role, catchall, disposable)

        if risk >= 70:
            status = "VALID"
        elif risk >= 30:
            status = "RISKY"
        else:
            status = "INVALID"

        RESULTS.append({
            "email": email,
            "status": status,
            "dns": "OK" if dns_ok else "FAIL",
            "smtp": smtp_code,
            "role": "YES" if role else "NO",
            "catchall": "YES" if catchall else "NO",
            "risk": risk
        })

        PROGRESS["done"] += 1
        time.sleep(random.uniform(DELAY_MIN, DELAY_MAX))
        TASK_QUEUE.task_done()

# ===============================
# ROUTES
# ===============================
@app.route('/')
def index():
    return render_template_string(HTML)


@app.route('/start', methods=['POST'])
def start():
    global RUNNING, RESULTS, PROGRESS
    RESULTS.clear()
    PROGRESS = {"total": 0, "done": 0}

    lines = request.files['file'].read().decode(errors='ignore').splitlines()
    emails = [e.strip() for e in lines if syntax_ok(e.strip())]

    PROGRESS["total"] = len(emails)
    for e in emails:
        TASK_QUEUE.put(e)

    RUNNING = True
    threading.Thread(target=worker, daemon=True).start()
    return ('', 204)


@app.route('/stream')
def stream():
    def event_stream():
        sent = 0
        while RUNNING:
            if sent < len(RESULTS):
                r = RESULTS[sent]
                sent += 1
                yield f"data: {json.dumps({'type':'result', **r})}\n\n"
            yield f"data: {json.dumps({'type':'progress', **PROGRESS})}\n\n"
            if PROGRESS['done'] >= PROGRESS['total']:
                break
            time.sleep(0.2)
    return Response(event_stream(), mimetype='text/event-stream')


if __name__ == '__main__':
    app.run(debug=True, threaded=True)
