# ===============================
# FILE: app.py (STABLE ENTERPRISE LOCAL SMTP VERIFIER)
# ===============================
# Run: python app.py
# Open: http://127.0.0.1:5000

import re
import time
import random
import dns.resolver
import smtplib
from flask import Flask, request, jsonify, render_template_string

# ===============================
# APP INIT
# ===============================
app = Flask(__name__)

# ===============================
# CONFIG
# ===============================
SMTP_TIMEOUT = 10
DELAY_MIN = 0.5
DELAY_MAX = 1.5
SAFE_MAIL_FROM = "check@localhost"
HELO_HOST = "localhost"

ROLE_ACCOUNTS = {"admin","info","support","sales","contact","abuse"}
EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$")

# ===============================
# UI (FULL DASHBOARD)
# ===============================
HTML = """
<!DOCTYPE html>
<html>
<head>
<title>Local Enterprise SMTP Email Verifier</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
<style>
body{margin:0;font-family:Inter;background:#0b0f1a;color:#fff}
header{padding:20px;background:#111827;font-size:22px;font-weight:800}
.container{padding:20px}
.card{background:#111827;border-radius:14px;padding:20px;margin-bottom:20px}
input,button{padding:12px;border-radius:8px;border:none;font-size:14px}
button{background:#22d3ee;color:#000;font-weight:700;cursor:pointer}
.progress{height:10px;background:#1f2937;border-radius:10px;overflow:hidden;margin-top:10px}
.progress-bar{height:100%;width:0%;background:#22d3ee}
.stats{display:flex;gap:15px;margin-top:15px}
.stat{flex:1;background:#020617;padding:15px;border-radius:10px;text-align:center}
table{width:100%;border-collapse:collapse;margin-top:20px}
th,td{padding:10px;border-bottom:1px solid #1f2937}
th{color:#67e8f9;text-align:left}
.valid{color:#22c55e}
.invalid{color:#ef4444}
.risky{color:#facc15}
</style>
</head>
<body>
<header>Enterprise Local SMTP Email Verification Engine</header>
<div class="container">
<div class="card">
<input type="file" id="file"> <button onclick="start()">Start Verification</button>
<div class="progress"><div id="bar" class="progress-bar"></div></div>
<div class="stats">
<div class="stat">VALID<br><span id="v">0</span></div>
<div class="stat">RISKY<br><span id="r">0</span></div>
<div class="stat">INVALID<br><span id="i">0</span></div>
</div>
</div>
<div class="card">
<table id="table"><tr><th>Email</th><th>Status</th><th>SMTP</th><th>Role</th><th>Risk</th></tr></table>
</div>
</div>
<script>
function start(){
 let f=document.getElementById('file').files[0];
 if(!f){alert('Upload a file');return;}
 let fd=new FormData();fd.append('file',f);
 fetch('/verify',{method:'POST',body:fd})
 .then(r=>r.json()).then(d=>render(d));
}
function render(data){
 let total=data.length,done=0,v=0,r=0,i=0;
 data.forEach(x=>{
 done++;
 if(x.status=='VALID')v++;
 if(x.status=='RISKY')r++;
 if(x.status=='INVALID')i++;
 document.getElementById('v').innerText=v;
 document.getElementById('r').innerText=r;
 document.getElementById('i').innerText=i;
 document.getElementById('bar').style.width=(done/total*100)+'%';
 let row=document.getElementById('table').insertRow(-1);
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
def syntax_valid(email):
    return EMAIL_REGEX.match(email)


def role_check(email):
    return email.split('@')[0].lower() in ROLE_ACCOUNTS


def mx_lookup(domain):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        return sorted([r.exchange.to_text() for r in answers])
    except:
        return []


def smtp_check(email, mx):
    try:
        server = smtplib.SMTP(timeout=SMTP_TIMEOUT)
        server.connect(mx)
        server.helo(HELO_HOST)
        server.mail(SAFE_MAIL_FROM)
        code, _ = server.rcpt(email)
        server.quit()
        return code
    except:
        return 0


def risk_score(code, role):
    score = 50
    if code == 250:
        score += 35
    if role:
        score -= 15
    if code in [550, 551, 553]:
        score = 5
    return max(0, min(100, score))


# ===============================
# ROUTES
# ===============================
@app.route('/')
def index():
    return render_template_string(HTML)


@app.route('/verify', methods=['POST'])
def verify():
    lines = request.files['file'].read().decode(errors='ignore').splitlines()
    results = []
    for email in lines:
        email = email.strip()
        if not email:
            continue

        if not syntax_valid(email):
            results.append({"email": email, "status": "INVALID", "code": "SYNTAX", "role": "NO", "risk": 0})
            continue

        domain = email.split('@')[1]
        mxs = mx_lookup(domain)
        if not mxs:
            results.append({"email": email, "status": "INVALID", "code": "NO_MX", "role": "NO", "risk": 0})
            continue

        role = role_check(email)
        code = smtp_check(email, mxs[0])
        risk = risk_score(code, role)

        if risk >= 70:
            status = "VALID"
        elif risk >= 30:
            status = "RISKY"
        else:
            status = "INVALID"

        results.append({
            "email": email,
            "status": status,
            "code": code,
            "role": "YES" if role else "NO",
            "risk": risk
        })

        time.sleep(random.uniform(DELAY_MIN, DELAY_MAX))

    return jsonify(results)


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
