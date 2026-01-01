import os
import re
import time
import json
import random
import queue
import threading
import sqlite3
import smtplib
import socket
import logging
import base64
import hashlib
import ssl
import requests
from datetime import datetime
from io import StringIO, BytesIO
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

import dns.resolver
from flask import Flask, request, Response, render_template_string, jsonify, send_file

# ===============================
# 1. CORE CONFIGURATION & STATE
# ===============================
app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

DATABASE_NAME = "titan_quantum_ultimate.db"
CONCURRENT_VERIFIERS = 40
SMTP_TIMEOUT = 12
USER_AGENT = "TitanQuantum/5.0 (Absolute Intelligence)"

# Internal Messaging Queues
VERIFY_QUEUE = queue.Queue()
SEND_QUEUE = queue.Queue()
LOG_QUEUE = queue.Queue()

# Thread-Safe Global State
class GlobalState:
    def __init__(self):
        self.results = []
        self.stats = {
            "v_total": 0, "v_done": 0, "v_valid": 0, "v_risky": 0, "v_invalid": 0,
            "s_total": 0, "s_done": 0, "s_success": 0, "s_fail": 0,
            "is_verifying": False, "is_sending": False, "ai_analyzing": False
        }
        self.ai_report = ""
        self.lock = threading.Lock()

state = GlobalState()

# ===============================
# 2. DATASETS & HEURISTICS
# ===============================
ROLE_KEYS = {"admin", "support", "info", "sales", "billing", "hr", "noreply", "no-reply", "webmaster", "postmaster"}
DISPOSABLE_DOMAINS = {"mailinator.com", "yopmail.com", "tempmail.org", "guerrillamail.com", "10minutemail.com", "trashmail.com"}
HIGH_RISK_TLDS = {".xyz", ".top", ".stream", ".icu", ".work", ".bid", ".date", ".win", ".loan", ".racing"}

# ===============================
# 3. DATABASE ARCHITECTURE
# ===============================
def init_db():
    conn = sqlite3.connect(DATABASE_NAME)
    c = conn.cursor()
    # Verification Table
    c.execute("""CREATE TABLE IF NOT EXISTS verified (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT, status TEXT, score INTEGER, provider TEXT, reasons TEXT, ts DATETIME
    )""")
    # Campaign History
    c.execute("""CREATE TABLE IF NOT EXISTS campaign_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        recipient TEXT, subject TEXT, status TEXT, error TEXT, ts DATETIME
    )""")
    # Persistent Settings
    c.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)")
    # Default API Settings
    c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('gemini_api_key', '')")
    conn.commit()
    conn.close()

init_db()

# ===============================
# 4. GEMINI ARTIFICIAL INTELLIGENCE
# ===============================
class TitanAI:
    @staticmethod
    def get_key():
        conn = sqlite3.connect(DATABASE_NAME)
        res = conn.execute("SELECT value FROM settings WHERE key='gemini_api_key'").fetchone()
        conn.close()
        return res[0] if res else ""

    @staticmethod
    def deep_analyze(emails):
        api_key = TitanAI.get_key()
        if not api_key: return "GEMINI_ERROR: No API Key found in settings."

        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-09-2025:generateContent?key={api_key}"
        
        # We sample the list to stay within token limits while maintaining context
        sample_size = min(len(emails), 150)
        sample = random.sample(emails, sample_size)
        
        prompt = f"""
        Act as an Enterprise Cyber-Security Expert. 
        Analyze this email list for:
        1. Linguistic entropy (random character strings vs human names).
        2. Detection of common 'Honey-pot' seeds used by ISPs.
        3. TLD risk assessment.
        4. Give a 'Deliverability Probability' percentage.
        
        Emails to analyze: {', '.join(sample)}
        """
        
        payload = {"contents": [{"parts": [{"text": prompt}]}]}

        # Exponential Backoff for API stability
        for delay in [1, 2, 4]:
            try:
                response = requests.post(url, json=payload, timeout=25)
                if response.status_code == 200:
                    data = response.json()
                    return data['candidates'][0]['content']['parts'][0]['text']
            except Exception as e:
                time.sleep(delay)
        return "GEMINI_ERROR: Failed to communicate with AI Engine."

# ===============================
# 5. SMTP STATE-MACHINE PROBER
# ===============================
class QuantumProber:
    @staticmethod
    def check(email):
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            return 0, "INVALID", "N/A", "RFC Syntax Violation"
        
        user, domain = email.split('@')
        score = 80
        reasons = []

        # Heuristic 1: Disposable Check
        if domain.lower() in DISPOSABLE_DOMAINS:
            return 10, "INVALID", "N/A", "Disposable Domain Detected"

        # Heuristic 2: Role Check
        if user.lower() in ROLE_KEYS:
            score -= 20
            reasons.append("Role-based Account")

        # Heuristic 3: DNS/MX Probing
        try:
            mx_records = dns.resolver.resolve(domain, 'MX', timeout=8)
            mx_hosts = sorted([(r.preference, str(r.exchange).rstrip('.')) for r in mx_records])
            target_mx = mx_hosts[0][1]
        except Exception:
            return 0, "INVALID", "N/A", "No MX Records Found"

        # Heuristic 4: Direct SMTP Handshake
        try:
            # We connect to verify mailbox existence without sending mail
            with smtplib.SMTP(target_mx, timeout=SMTP_TIMEOUT) as server:
                server.helo("quantum.titan-enterprise.com")
                server.mail("probe@titan-enterprise.com")
                code, message = server.rcpt(email)
                
                # Check for Catch-all (Anti-Spam Trap)
                # We probe a non-existent sibling to see if the server lies
                fake_user = f"detect_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"
                f_code, _ = server.rcpt(f"{fake_user}@{domain}")
                
                if f_code == 250:
                    score -= 40
                    reasons.append("Catch-all Domain (Low Precision)")

                if code == 250:
                    score += 20
                    status = "VALID" if score >= 70 else "RISKY"
                    reasons.append("Handshake Successful")
                elif code in [450, 451, 452]:
                    status = "RISKY"
                    reasons.append("Server Greylisting (451)")
                else:
                    status = "INVALID"
                    reasons.append(f"SMTP Reject: {code}")
                    
        except Exception as e:
            status = "RISKY"
            reasons.append(f"Conn Error: {str(e)[:20]}")

        final_score = max(0, min(100, score))
        return final_score, status, target_mx, " | ".join(reasons)

# ===============================
# 6. THREADED WORKERS
# ===============================
def verifier_loop():
    while True:
        try: email = VERIFY_QUEUE.get(timeout=2)
        except:
            if not state.stats["is_verifying"]: break
            continue
        
        score, status, provider, reasons = QuantumProber.check(email)
        
        data = {
            "email": email, "status": status, "score": score, 
            "provider": provider, "reasons": reasons,
            "ts": datetime.now().strftime("%H:%M:%S")
        }

        with state.lock:
            state.results.append(data)
            state.stats["v_done"] += 1
            state.stats[f"v_{status.lower()}"] += 1
            # Log to DB
            try:
                conn = sqlite3.connect(DATABASE_NAME)
                conn.execute("INSERT INTO verified (email, status, score, provider, reasons, ts) VALUES (?,?,?,?,?,?)",
                             (email, status, score, provider, reasons, datetime.now()))
                conn.commit()
                conn.close()
            except: pass
            
        VERIFY_QUEUE.task_done()

def mailer_loop(smtp_config, subject, body, attachment=None):
    while not SEND_QUEUE.empty():
        recipient = SEND_QUEUE.get()
        status = "SENT"
        error_msg = ""
        
        try:
            msg = MIMEMultipart()
            msg['From'] = smtp_config['user']
            msg['To'] = recipient
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'html'))
            
            if attachment:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(base64.b64decode(attachment['data']))
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', f"attachment; filename={attachment['name']}")
                msg.attach(part)
            
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context, timeout=20) as server:
                server.login(smtp_config['user'], smtp_config['pass'])
                server.sendmail(smtp_config['user'], recipient, msg.as_string())
            
            with state.lock: state.stats["s_success"] += 1
        except Exception as e:
            status = "FAILED"
            error_msg = str(e)
            with state.lock: state.stats["s_fail"] += 1
            
        with state.lock:
            state.stats["s_done"] += 1
            try:
                conn = sqlite3.connect(DATABASE_NAME)
                conn.execute("INSERT INTO campaign_logs (recipient, subject, status, error, ts) VALUES (?,?,?,?,?)",
                             (recipient, subject, status, error_msg, datetime.now()))
                conn.commit()
                conn.close()
            except: pass
            
        SEND_QUEUE.task_done()
        # Strategic Pacing for ISP compliance
        time.sleep(random.uniform(1.5, 4.0))

# ===============================
# 7. THE QUANTUM DASHBOARD (HTML)
# ===============================
UI_HTML = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Titan Quantum | Absolute Intelligence Suite</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;600;800&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root { --brand: #3b82f6; --bg: #030712; }
        body { 
            background: var(--bg); color: #e2e8f0; font-family: 'Plus Jakarta Sans', sans-serif;
            background-image: radial-gradient(circle at 50% 0%, #111827 0%, #030712 100%);
        }
        .mono { font-family: 'Fira Code', monospace; }
        .glass { background: rgba(15, 23, 42, 0.6); backdrop-filter: blur(12px); border: 1px solid rgba(255,255,255,0.05); }
        .btn-glow { box-shadow: 0 0 20px rgba(59, 130, 246, 0.3); transition: all 0.3s; }
        .btn-glow:hover { transform: translateY(-2px); box-shadow: 0 0 30px rgba(59, 130, 246, 0.5); }
        .tab-active { color: #3b82f6; border-bottom: 2px solid #3b82f6; }
        
        ::-webkit-scrollbar { width: 5px; }
        ::-webkit-scrollbar-thumb { background: #1e293b; border-radius: 10px; }

        @keyframes slide-in { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        .animate-slide { animation: slide-in 0.4s ease-out forwards; }
    </style>
</head>
<body class="min-h-screen">

    <!-- TOP NAV -->
    <nav class="glass sticky top-0 z-50 border-b border-white/5 px-8 py-4 flex justify-between items-center">
        <div class="flex items-center gap-4">
            <div class="w-10 h-10 bg-blue-600 rounded-xl flex items-center justify-center shadow-lg shadow-blue-500/20">
                <i class="fas fa-shield-virus text-white"></i>
            </div>
            <div>
                <h1 class="text-lg font-extrabold uppercase tracking-tight">Titan <span class="text-blue-500">Quantum</span></h1>
                <p class="text-[9px] text-slate-500 font-black tracking-widest">ABSOLUTE ENTERPRISE v5.0</p>
            </div>
        </div>

        <div class="hidden lg:flex items-center gap-10">
            <button onclick="nav('v')" id="nav-v" class="tab-active py-1 text-xs font-bold uppercase tracking-widest hover:text-blue-400 transition">Verifier</button>
            <button onclick="nav('m')" id="nav-m" class="py-1 text-xs font-bold uppercase tracking-widest hover:text-blue-400 transition">Bulk Mailer</button>
            <button onclick="nav('a')" id="nav-a" class="py-1 text-xs font-bold uppercase tracking-widest hover:text-blue-400 transition">AI Analysis</button>
            <button onclick="nav('s')" id="nav-s" class="py-1 text-xs font-bold uppercase tracking-widest hover:text-blue-400 transition">Settings</button>
        </div>

        <div class="flex items-center gap-4">
            <div class="text-right">
                <div id="sys-clock" class="text-xs font-bold mono">00:00:00</div>
                <div class="text-[9px] text-emerald-500 font-bold uppercase">System Nominal</div>
            </div>
        </div>
    </nav>

    <main class="max-w-[1500px] mx-auto p-6 lg:p-10 space-y-10">

        <!-- TAB: VERIFIER -->
        <section id="tab-v" class="animate-slide space-y-8">
            <div class="grid grid-cols-1 md:grid-cols-4 gap-6">
                <div class="glass p-6 rounded-3xl relative overflow-hidden group">
                    <div class="absolute -right-4 -top-4 text-blue-500/10 text-6xl group-hover:scale-110 transition-transform"><i class="fas fa-microchip"></i></div>
                    <p class="text-[10px] font-black text-slate-500 uppercase mb-1">Queue State</p>
                    <div class="text-3xl font-bold" id="v-stat-done">0 / 0</div>
                    <div class="w-full bg-white/5 h-1 mt-4 rounded-full overflow-hidden">
                        <div id="v-progress" class="bg-blue-600 h-full transition-all duration-500" style="width:0%"></div>
                    </div>
                </div>
                <div class="glass p-6 rounded-3xl border-l-4 border-emerald-500">
                    <p class="text-[10px] font-black text-emerald-500 uppercase mb-1">Validated Pure</p>
                    <div class="text-3xl font-bold text-emerald-400" id="v-stat-valid">0</div>
                </div>
                <div class="glass p-6 rounded-3xl border-l-4 border-amber-500">
                    <p class="text-[10px] font-black text-amber-500 uppercase mb-1">Risky Handshake</p>
                    <div class="text-3xl font-bold text-amber-400" id="v-stat-risky">0</div>
                </div>
                <div class="glass p-6 rounded-3xl border-l-4 border-rose-500">
                    <p class="text-[10px] font-black text-rose-500 uppercase mb-1">Bounced / Dead</p>
                    <div class="text-3xl font-bold text-rose-400" id="v-stat-invalid">0</div>
                </div>
            </div>

            <div class="grid lg:grid-cols-12 gap-8">
                <div class="lg:col-span-4 space-y-6">
                    <div class="glass p-8 rounded-3xl shadow-xl">
                        <h3 class="text-sm font-black uppercase tracking-widest text-blue-500 mb-6">Quantum Input</h3>
                        <textarea id="v-input" class="w-full h-80 bg-slate-900/50 border border-white/10 rounded-2xl p-4 text-sm mono focus:ring-2 focus:ring-blue-500 outline-none transition-all" placeholder="Enter emails...&#10;user@domain.com"></textarea>
                        <div class="grid grid-cols-2 gap-4 mt-6">
                            <button onclick="clearV()" class="py-4 rounded-2xl bg-white/5 font-bold text-xs uppercase hover:bg-white/10 transition">Clear</button>
                            <button onclick="startV()" id="btn-v" class="bg-blue-600 py-4 rounded-2xl font-black text-xs uppercase tracking-widest btn-glow">Execute Scan</button>
                        </div>
                    </div>
                </div>
                <div class="lg:col-span-8">
                    <div class="glass rounded-3xl overflow-hidden flex flex-col h-[550px]">
                        <div class="p-6 border-b border-white/5 flex justify-between items-center bg-white/[0.02]">
                            <h3 class="text-sm font-bold flex items-center gap-2">
                                <span class="w-2 h-2 rounded-full bg-blue-500 animate-pulse"></span> Intelligence Feed
                            </h3>
                            <div class="flex gap-2">
                                <button onclick="dl('VALID')" class="bg-emerald-500/10 text-emerald-400 text-[10px] font-black px-4 py-2 rounded-xl border border-emerald-500/20">Valid CSV</button>
                                <button onclick="dl('INVALID')" class="bg-rose-500/10 text-rose-400 text-[10px] font-black px-4 py-2 rounded-xl border border-rose-500/20">Dead CSV</button>
                            </div>
                        </div>
                        <div class="flex-1 overflow-y-auto">
                            <table class="w-full text-left text-xs">
                                <thead class="sticky top-0 bg-slate-900 font-black uppercase text-slate-500">
                                    <tr>
                                        <th class="p-6">Target</th>
                                        <th class="p-6">Score</th>
                                        <th class="p-6">Provider</th>
                                        <th class="p-6 text-right">Result</th>
                                    </tr>
                                </thead>
                                <tbody id="v-table" class="divide-y divide-white/5"></tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <!-- TAB: BULK MAILER -->
        <section id="tab-m" class="hidden animate-slide space-y-8">
            <div class="grid lg:grid-cols-12 gap-8">
                <div class="lg:col-span-4 space-y-6">
                    <div class="glass p-8 rounded-3xl">
                        <h3 class="text-sm font-black uppercase tracking-widest text-blue-500 mb-6">SMTP Gateway</h3>
                        <div class="space-y-4">
                            <input type="email" id="m-user" placeholder="SMTP Username (e.g. Gmail)" class="w-full bg-slate-900 border border-white/10 p-4 rounded-xl text-sm">
                            <input type="password" id="m-pass" placeholder="App Password" class="w-full bg-slate-900 border border-white/10 p-4 rounded-xl text-sm">
                            <div class="pt-4 border-t border-white/5">
                                <p class="text-[10px] font-bold text-slate-500 uppercase mb-2">Recipient Array</p>
                                <textarea id="m-recips" class="w-full h-48 bg-slate-900 border border-white/10 p-4 rounded-xl text-xs mono" placeholder="Paste validated list..."></textarea>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="lg:col-span-8 space-y-6">
                    <div class="glass p-8 rounded-3xl">
                        <h3 class="text-sm font-black uppercase tracking-widest text-blue-500 mb-6">Campaign Architect</h3>
                        <div class="space-y-4">
                            <input type="text" id="m-sub" placeholder="Subject Line" class="w-full bg-slate-900 border border-white/10 p-4 rounded-xl font-bold">
                            <textarea id="m-body" class="w-full h-64 bg-slate-900 border border-white/10 p-4 rounded-xl text-sm" placeholder="HTML Email Content..."></textarea>
                            
                            <div class="flex justify-between items-center pt-4">
                                <label class="cursor-pointer bg-white/5 px-6 py-3 rounded-xl border border-white/10 hover:bg-white/10 transition text-xs font-bold uppercase">
                                    <i class="fas fa-paperclip mr-2"></i> <span id="file-label">Attach File</span>
                                    <input type="file" id="m-attach" class="hidden" onchange="upFile(this)">
                                </label>
                                <button onclick="launchCampaign()" id="btn-m" class="bg-blue-600 px-10 py-4 rounded-2xl font-black text-xs uppercase tracking-widest btn-glow">Launch Deployment</button>
                            </div>
                        </div>

                        <div id="m-progress-box" class="hidden mt-8 p-6 bg-blue-500/5 rounded-2xl border border-blue-500/10">
                            <div class="flex justify-between items-end mb-2">
                                <p id="m-progress-text" class="text-xs font-bold uppercase">Deploying 0 / 0</p>
                                <p id="m-perc" class="text-xs font-bold mono">0%</p>
                            </div>
                            <div class="w-full h-1.5 bg-white/5 rounded-full overflow-hidden">
                                <div id="m-bar" class="bg-blue-600 h-full transition-all duration-700" style="width:0%"></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <!-- TAB: AI ANALYSIS -->
        <section id="tab-a" class="hidden animate-slide space-y-8">
            <div class="max-w-4xl mx-auto glass p-10 rounded-3xl text-center space-y-6">
                <div class="w-20 h-20 bg-indigo-600/20 text-indigo-500 rounded-full flex items-center justify-center mx-auto text-3xl">
                    <i class="fas fa-brain"></i>
                </div>
                <h2 class="text-2xl font-black uppercase tracking-tighter">Gemini Quantum <span class="text-indigo-500">Analysis</span></h2>
                <p class="text-slate-400 text-sm max-w-xl mx-auto italic">
                    Utilize the Gemini 2.5 Flash model to detect adversarial patterns, high-risk TLD distributions, and honeypot seeds within your dataset.
                </p>
                <button onclick="runAI()" id="btn-ai" class="bg-indigo-600 px-12 py-4 rounded-2xl font-black text-xs uppercase tracking-widest btn-glow">Compute Intelligence</button>
                
                <div id="ai-output" class="hidden text-left bg-slate-900/50 p-8 rounded-3xl border border-indigo-500/20 text-slate-300 text-sm leading-relaxed whitespace-pre-wrap mono">
                    Awaiting computation...
                </div>
            </div>
        </section>

        <!-- TAB: SETTINGS -->
        <section id="tab-s" class="hidden animate-slide">
            <div class="max-w-2xl mx-auto glass p-10 rounded-3xl space-y-8">
                <h2 class="text-xl font-black uppercase tracking-tight flex items-center gap-3">
                    <i class="fas fa-cogs text-blue-500"></i> System Configuration
                </h2>
                <div class="space-y-4">
                    <div class="space-y-2">
                        <label class="text-[10px] font-black text-slate-500 uppercase">Gemini AI API Key</label>
                        <input type="password" id="s-gemini" placeholder="Enter API Key..." class="w-full bg-slate-900 border border-white/10 p-4 rounded-xl text-sm focus:border-blue-500 outline-none">
                    </div>
                    <button onclick="saveS()" class="w-full bg-white text-black font-black py-4 rounded-2xl hover:bg-slate-200 transition text-xs uppercase">Save Securely</button>
                </div>
            </div>
        </section>

    </main>

    <script>
        let es = null;

        function nav(id) {
            ['v','m','a','s'].forEach(t => {
                document.getElementById('tab-'+t).classList.add('hidden');
                document.getElementById('nav-'+t).classList.remove('tab-active');
            });
            document.getElementById('tab-'+id).classList.remove('hidden');
            document.getElementById('nav-'+id).classList.add('tab-active');
            if(id === 's') loadS();
        }

        function startV() {
            const emails = document.getElementById('v-input').value.split('\\n').filter(x => x.trim());
            if(emails.length === 0) return;
            document.getElementById('v-table').innerHTML = '';
            document.getElementById('btn-v').disabled = true;
            document.getElementById('btn-v').innerText = "PROBING...";
            fetch('/api/v', {
                method: 'POST',
                headers: {'Content-Type':'application/json'},
                body: JSON.stringify({emails})
            }).then(() => connect());
        }

        function connect() {
            if(es) es.close();
            es = new EventSource('/api/stream');
            es.onmessage = (e) => {
                const d = JSON.parse(e.data);
                if(d.type === 'stats') {
                    document.getElementById('v-stat-done').innerText = `${d.v_done} / ${d.v_total}`;
                    document.getElementById('v-stat-valid').innerText = d.v_valid;
                    document.getElementById('v-stat-risky').innerText = d.v_risky;
                    document.getElementById('v-stat-invalid').innerText = d.v_invalid;
                    document.getElementById('v-progress').style.width = (d.v_done/d.v_total)*100 + '%';
                    
                    if(d.is_sending) {
                        document.getElementById('m-progress-box').classList.remove('hidden');
                        document.getElementById('m-progress-text').innerText = `Deploying ${d.s_done} / ${d.s_total}`;
                        document.getElementById('m-perc').innerText = Math.round((d.s_done/d.s_total)*100) + '%';
                        document.getElementById('m-bar').style.width = (d.s_done/d.s_total)*100 + '%';
                    }

                    if(d.v_done >= d.v_total && d.v_total > 0) {
                        document.getElementById('btn-v').disabled = false;
                        document.getElementById('btn-v').innerText = "Execute Scan";
                    }
                } else if(d.type === 'res') {
                    const t = document.getElementById('v-table');
                    const r = document.createElement('tr');
                    const c = d.status === 'VALID' ? 'text-emerald-400' : (d.status === 'RISKY' ? 'text-amber-400' : 'text-rose-400');
                    r.className = "hover:bg-white/[0.02] transition-colors";
                    r.innerHTML = `
                        <td class="p-6 font-bold">${d.email}<br><span class="text-[9px] text-slate-500 font-normal italic">${d.reasons}</span></td>
                        <td class="p-6 mono">${d.score}%</td>
                        <td class="p-6 text-slate-500 uppercase text-[10px] font-bold">${d.provider}</td>
                        <td class="p-6 text-right font-black ${c}">${d.status}</td>
                    `;
                    t.prepend(r);
                }
            };
        }

        function runAI() {
            const emails = document.getElementById('v-input').value.split('\\n').filter(x => x.trim());
            if(emails.length === 0) return;
            document.getElementById('btn-ai').disabled = true;
            document.getElementById('btn-ai').innerText = "THINKING...";
            document.getElementById('ai-output').classList.remove('hidden');
            document.getElementById('ai-output').innerText = "Analyzing list patterns with Gemini 2.5...";
            
            fetch('/api/ai', {
                method: 'POST',
                headers: {'Content-Type':'application/json'},
                body: JSON.stringify({emails})
            }).then(r => r.json()).then(d => {
                document.getElementById('ai-output').innerText = d.report;
                document.getElementById('btn-ai').disabled = false;
                document.getElementById('btn-ai').innerText = "Compute Intelligence";
            });
        }

        async function launchCampaign() {
            const user = document.getElementById('m-user').value;
            const pass = document.getElementById('m-pass').value;
            const sub = document.getElementById('m-sub').value;
            const body = document.getElementById('m-body').value;
            const recips = document.getElementById('m-recips').value.split('\\n').filter(x => x.trim());
            
            if(!user || !pass || recips.length === 0) return alert("Missing Config");

            const payload = { user, pass, subject: sub, body, recipients: recips };
            const file = document.getElementById('m-attach').files[0];
            
            if(file) {
                const reader = new FileReader();
                reader.onload = () => {
                    payload.attachment = { name: file.name, data: reader.result.split(',')[1] };
                    executeSend(payload);
                };
                reader.readAsDataURL(file);
            } else {
                executeSend(payload);
            }
        }

        function executeSend(p) {
            fetch('/api/send', {
                method: 'POST',
                headers: {'Content-Type':'application/json'},
                body: JSON.stringify(p)
            }).then(() => connect());
        }

        function saveS() {
            const key = document.getElementById('s-gemini').value;
            fetch('/api/save-s', {
                method: 'POST',
                headers: {'Content-Type':'application/json'},
                body: JSON.stringify({gemini_api_key: key})
            }).then(() => alert("Settings Updated."));
        }

        function loadS() {
            fetch('/api/get-s').then(r => r.json()).then(d => {
                document.getElementById('s-gemini').value = d.gemini_api_key || "";
            });
        }

        function upFile(i) { document.getElementById('file-label').innerText = i.files[0].name; }
        function dl(s) { window.location = '/api/dl/' + s; }
        function clearV() { document.getElementById('v-input').value = ''; }

        setInterval(() => {
            const n = new Date();
            document.getElementById('sys-clock').innerText = n.toLocaleTimeString();
        }, 1000);
    </script>
</body>
</html>
"""

# ===============================
# 8. API ENDPOINTS
# ===============================
@app.route('/')
def index(): return render_template_string(UI_HTML)

@app.route('/api/v', methods=['POST'])
def api_v():
    data = request.json
    emails = list(set([e.strip() for e in data['emails'] if '@' in e]))
    with state.lock:
        state.results = []
        state.stats.update({"v_total": len(emails), "v_done": 0, "v_valid": 0, "v_risky": 0, "v_invalid": 0, "is_verifying": True})
        for e in emails: VERIFY_QUEUE.put(e)
    
    for _ in range(min(CONCURRENT_VERIFIERS, len(emails))):
        threading.Thread(target=verifier_loop, daemon=True).start()
    return jsonify({"status": "queued"})

@app.route('/api/ai', methods=['POST'])
def api_ai():
    emails = request.json.get('emails', [])
    report = TitanAI.deep_analyze(emails)
    return jsonify({"report": report})

@app.route('/api/send', methods=['POST'])
def api_send():
    data = request.json
    recips = data['recipients']
    with state.lock:
        state.stats.update({"s_total": len(recips), "s_done": 0, "s_success": 0, "s_fail": 0, "is_sending": True})
        for r in recips: SEND_QUEUE.put(r)
    
    smtp_conf = {"user": data['user'], "pass": data['pass']}
    threading.Thread(target=mailer_loop, args=(smtp_conf, data['subject'], data['body'], data.get('attachment')), daemon=True).start()
    return jsonify({"status": "deployed"})

@app.route('/api/stream')
def api_stream():
    def gen():
        last_idx = 0
        while True:
            with state.lock:
                if last_idx < len(state.results):
                    for i in range(last_idx, len(state.results)):
                        yield f"data: {json.dumps({'type': 'res', **state.results[i]})}\n\n"
                    last_idx = len(state.results)
                
                yield f"data: {json.dumps({'type': 'stats', **state.stats})}\n\n"
                
                # Exit when both processes finish
                v_done = (state.stats["v_done"] >= state.stats["v_total"] and state.stats["v_total"] > 0)
                s_done = (state.stats["s_done"] >= state.stats["s_total"] and state.stats["s_total"] > 0)
                if v_done and (not state.stats["is_sending"] or s_done): break
            time.sleep(1)
    return Response(gen(), mimetype='text/event-stream')

@app.route('/api/save-s', methods=['POST'])
def save_s():
    data = request.json
    conn = sqlite3.connect(DATABASE_NAME)
    for k, v in data.items():
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?,?)", (k, v))
    conn.commit()
    conn.close()
    return jsonify({"status": "saved"})

@app.route('/api/get-s')
def get_s():
    conn = sqlite3.connect(DATABASE_NAME)
    rows = conn.execute("SELECT key, value FROM settings").fetchall()
    conn.close()
    return jsonify(dict(rows))

@app.route('/api/dl/<status>')
def dl(status):
    conn = sqlite3.connect(DATABASE_NAME)
    rows = conn.execute("SELECT email FROM verified WHERE status = ?", (status,)).fetchall()
    conn.close()
    si = StringIO()
    si.write("email\n")
    for r in rows: si.write(f"{r[0]}\n")
    return Response(si.getvalue(), mimetype="text/csv", headers={"Content-disposition": f"attachment; filename=titan_{status.lower()}.csv"})

if __name__ == '__main__':
    app.run(port=5000, threaded=True)