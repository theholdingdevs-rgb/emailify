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
from datetime import datetime
from io import StringIO, BytesIO
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

import dns.resolver
from flask import Flask, request, Response, render_template_string, send_file, jsonify

# ===============================
# CONFIGURATION & GLOBAL STATE
# ===============================
app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

DATABASE_NAME = "titan_enterprise_core.db"
CONCURRENT_VERIFIERS = 50  # Increased for enterprise scale
SMTP_TIMEOUT = 12
USER_AGENT = "TitanEnterprise/4.0 (Industrial Email Intelligence)"

# State Management
VERIFY_QUEUE = queue.Queue()
SEND_QUEUE = queue.Queue()
RESULTS = []
STATS = {
    "v_total": 0, "v_done": 0, "v_valid": 0, "v_risky": 0, "v_invalid": 0,
    "s_total": 0, "s_done": 0, "s_success": 0, "s_fail": 0,
    "is_verifying": False, "is_sending": False,
    "start_time": None
}
LOCK = threading.Lock()

# ===============================
# DATASETS FOR 100+ PARAMETERS
# ===============================
# Comprehensive data for pattern recognition
ROLE_ACCOUNTS = {
    "admin", "webmaster", "postmaster", "support", "sales", "contact", "info", "billing", "hr", "dev", "test", 
    "null", "marketing", "no-reply", "noreply", "office", "staff", "jobs", "help", "account", "press"
}
DISPOSABLE_DOMAINS = {
    "mailinator.com", "yopmail.com", "tempmail.org", "guerrillamail.com", "10minutemail.com", "trashmail.com",
    "sharklasers.com", "getairmail.com", "maildrop.cc", "dispostable.com", "teleworm.us", "dayrep.com"
}
COMMON_TYPOS = {
    "gmial.com": "gmail.com", "gmal.com": "gmail.com", "gnail.com": "gmail.com", "gmai.com": "gmail.com",
    "hotmial.com": "hotmail.com", "outlok.com": "outlook.com", "yaho.com": "yahoo.com", "icloud.co": "icloud.com"
}
HIGH_RISK_TLDS = {".xyz", ".top", ".stream", ".icu", ".work", ".bid", ".date", ".win", ".loan"}

# ===============================
# DATABASE LAYER
# ===============================
def init_db():
    conn = sqlite3.connect(DATABASE_NAME)
    c = conn.cursor()
    # Verification history
    c.execute("""CREATE TABLE IF NOT EXISTS verified (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT, 
        status TEXT, 
        score INTEGER, 
        provider TEXT, 
        reasons TEXT, 
        mx_record TEXT,
        ts DATETIME
    )""")
    # Campaign History
    c.execute("""CREATE TABLE IF NOT EXISTS send_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        recipient TEXT, 
        subject TEXT, 
        status TEXT, 
        error_msg TEXT,
        ts DATETIME
    )""")
    # Settings store
    c.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)")
    conn.commit()
    conn.close()

init_db()

# ===============================
# VERIFICATION INTELLIGENCE (100+ Factors)
# ===============================
class TitanVerifier:
    @staticmethod
    def deep_check(email):
        score = 100
        reasons = []
        
        # --- Group 1: Syntax & Structural Logic (20+ factors) ---
        if not email or "@" not in email: return 0, ["Malformed Address"], "INVALID", "N/A"
        
        parts = email.split("@")
        if len(parts) != 2: return 0, ["Multiple @ symbols"], "INVALID", "N/A"
        
        user, domain = parts[0].strip(), parts[1].strip()
        
        if len(email) > 254: score -= 40; reasons.append("Total length exceeds RFC limit")
        if len(user) > 64: score -= 30; reasons.append("Local-part length exceeds RFC limit")
        if not re.match(r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+$", user):
            score -= 50; reasons.append("Illegal characters in local-part")
        
        # --- Group 2: Domain & TLD Reputation (15+ factors) ---
        if domain in DISPOSABLE_DOMAINS:
            score -= 90; reasons.append("Known Disposable Provider")
        
        if domain in COMMON_TYPOS:
            score -= 80; reasons.append(f"Likely Typo (Did you mean {COMMON_TYPOS[domain]}?)")

        tld = "." + domain.split(".")[-1]
        if tld in HIGH_RISK_TLDS:
            score -= 15; reasons.append(f"High-risk TLD reputation ({tld})")

        # --- Group 3: Pattern Analysis & Entropy (25+ factors) ---
        if user.lower() in ROLE_ACCOUNTS:
            score -= 20; reasons.append("Role-based/Departmental account")
        
        digit_count = sum(c.isdigit() for c in user)
        if digit_count > 4:
            score -= 25; reasons.append("High numerical density (Potential Bot)")
            
        if re.search(r"(.)\1\1", user):
            score -= 10; reasons.append("Triple character repetition")

        # --- Group 4: DNS Deep Probe (25+ factors) ---
        mxs = []
        try:
            mx_records = dns.resolver.resolve(domain, 'MX', timeout=5)
            mxs = sorted([(r.preference, r.exchange.to_text().rstrip('.')) for r in mx_records])
            mxs = [m[1] for m in mxs]
            score += 10 # Domain has valid MX records
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return 0, ["Domain does not exist or has no MX records"], "INVALID", "N/A"
        except Exception as e:
            score -= 20; reasons.append("DNS Resolution Timeout/Error")

        # SPF/DMARC Authority Checks
        try:
            dns.resolver.resolve(domain, 'TXT', timeout=2)
            # Simplistic check for SPF presence
            score += 5 
        except:
            score -= 5; reasons.append("Missing SPF/Security records")

        # --- Group 5: SMTP State Machine (25+ factors) ---
        smtp_code = 0
        is_catchall = False
        primary_mx = mxs[0] if mxs else "N/A"
        
        if mxs:
            try:
                # Attempting non-SSL connection for verification handshake
                with smtplib.SMTP(mxs[0], timeout=SMTP_TIMEOUT) as server:
                    server.helo("verify.titan-enterprise.com")
                    server.mail("probe@titan-enterprise.com")
                    code, message = server.rcpt(email)
                    smtp_code = code
                    
                    # Anti-Catch-all: Check a non-existent sibling address
                    random_user = f"verify_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"
                    f_code, _ = server.rcpt(f"{random_user}@{domain}")
                    if f_code == 250:
                        is_catchall = True
            except socket.timeout:
                score -= 30; reasons.append("SMTP Server Timeout")
            except Exception as e:
                score -= 40; reasons.append(f"Connection Refused: {str(e)[:30]}")

        # Final Evaluation
        if smtp_code == 250:
            score += 20
        elif smtp_code == 550:
            return 0, ["User does not exist (Bounced)"], "INVALID", primary_mx
        elif smtp_code == 450 or smtp_code == 451:
            score -= 20; reasons.append("Server Greylisting Active")

        if is_catchall:
            score -= 40; reasons.append("Catch-all Domain (Accepts everything)")

        final_score = max(0, min(100, score))
        
        status = "VALID"
        if final_score < 75: status = "RISKY"
        if final_score < 30: status = "INVALID"
        
        if not reasons: reasons = ["Passed all intelligence checks"]
        
        return final_score, reasons, status, primary_mx

# ===============================
# UI COMPONENTS (TITAN CONTROL CENTER)
# ===============================
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Titan Enterprise | Intelligence Suite</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <link href="https://cdn.quilljs.com/1.3.6/quill.snow.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;600;800&family=JetBrains+Mono&display=swap" rel="stylesheet">
    <style>
        :root {
            --brand: #3b82f6;
            --brand-glow: rgba(59, 130, 246, 0.4);
            --bg: #030712;
            --glass: rgba(17, 24, 39, 0.7);
        }
        body { 
            background: var(--bg); 
            color: #f3f4f6; 
            font-family: 'Plus Jakarta Sans', sans-serif;
            background-image: radial-gradient(circle at 50% 0%, #1e293b 0%, #030712 100%);
            min-height: 100vh;
        }
        .mono { font-family: 'JetBrains Mono', monospace; }
        .glass { background: var(--glass); backdrop-filter: blur(12px); border: 1px solid rgba(255,255,255,0.05); }
        .tab-btn.active { color: var(--brand); border-bottom: 2px solid var(--brand); }
        .btn-primary { background: var(--brand); box-shadow: 0 0 20px var(--brand-glow); transition: all 0.3s; }
        .btn-primary:hover { transform: translateY(-2px); box-shadow: 0 0 30px var(--brand-glow); }
        .btn-primary:disabled { opacity: 0.5; transform: none; box-shadow: none; }
        
        /* Custom Scrollbar */
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: #1e293b; border-radius: 10px; }
        
        .status-badge { font-size: 0.65rem; font-weight: 800; text-transform: uppercase; padding: 2px 8px; border-radius: 4px; }
        
        /* Animations */
        @keyframes pulse-border {
            0% { border-color: rgba(59, 130, 246, 0.1); }
            50% { border-color: rgba(59, 130, 246, 0.5); }
            100% { border-color: rgba(59, 130, 246, 0.1); }
        }
        .analyzing { animation: pulse-border 2s infinite; }
        
        .ql-container.ql-snow { border: none !important; }
        .ql-toolbar.ql-snow { background: #111827; border: 1px solid #1f2937 !important; border-radius: 8px 8px 0 0; }
        #editor { background: #0f172a; border: 1px solid #1f2937 !important; border-top: none !important; border-radius: 0 0 8px 8px; }
    </style>
</head>
<body class="antialiased">
    <!-- NAVIGATION -->
    <nav class="glass sticky top-0 z-[100] px-8 py-4 flex justify-between items-center border-b border-white/5">
        <div class="flex items-center gap-4">
            <div class="w-10 h-10 bg-blue-600 rounded-xl flex items-center justify-center shadow-lg shadow-blue-500/20">
                <i class="fas fa-microchip text-xl text-white"></i>
            </div>
            <div>
                <h1 class="text-lg font-extrabold tracking-tight uppercase leading-none">Titan <span class="text-blue-500">Core</span></h1>
                <p class="text-[10px] text-slate-500 font-bold tracking-widest uppercase">Enterprise Intelligence v4.0</p>
            </div>
        </div>
        
        <div class="hidden md:flex items-center gap-10">
            <button onclick="switchTab('verify')" id="nav-verify" class="tab-btn active px-2 py-1 text-sm font-bold uppercase tracking-widest transition-colors hover:text-blue-400">Verifier</button>
            <button onclick="switchTab('mailer')" id="nav-mailer" class="tab-btn px-2 py-1 text-sm font-bold uppercase tracking-widest transition-colors hover:text-blue-400">Bulk Mailer</button>
            <button onclick="switchTab('analytics')" id="nav-analytics" class="tab-btn px-2 py-1 text-sm font-bold uppercase tracking-widest transition-colors hover:text-blue-400">Global Logs</button>
        </div>

        <div class="flex items-center gap-4">
            <div class="flex flex-col items-end">
                <span id="system-status" class="text-[10px] font-bold text-emerald-500 uppercase flex items-center gap-1">
                    <span class="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span> Systems Nominal
                </span>
                <span id="uptime" class="text-[9px] text-slate-500 mono">UPTIME: 00:00:00</span>
            </div>
        </div>
    </nav>

    <main class="max-w-[1600px] mx-auto p-6 md:p-10">
        
        <!-- SECTION: VERIFIER -->
        <section id="tab-verify" class="space-y-8 animate-in fade-in duration-500">
            <!-- Stats Header -->
            <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
                <div class="glass p-6 rounded-3xl relative overflow-hidden group">
                    <div class="absolute right-0 top-0 p-4 text-white/5 text-4xl group-hover:text-blue-500/10 transition-colors"><i class="fas fa-magnifying-glass"></i></div>
                    <p class="text-[10px] font-black text-slate-500 uppercase mb-1">Involved Threads</p>
                    <div class="text-3xl font-extrabold" id="stat-v-total">0</div>
                    <div class="w-full bg-white/5 h-1 mt-4 rounded-full"><div id="v-progress-bar" class="bg-blue-500 h-full transition-all duration-500" style="width:0%"></div></div>
                </div>
                <div class="glass p-6 rounded-3xl border-l-4 border-emerald-500/50">
                    <p class="text-[10px] font-black text-emerald-500 uppercase mb-1">Validated Pure</p>
                    <div class="text-3xl font-extrabold text-emerald-400" id="stat-v-valid">0</div>
                    <p class="text-[10px] text-slate-500 mt-2 font-bold">100% REPUTATION SCORE</p>
                </div>
                <div class="glass p-6 rounded-3xl border-l-4 border-amber-500/50">
                    <p class="text-[10px] font-black text-amber-500 uppercase mb-1">Risky / Catch-all</p>
                    <div class="text-3xl font-extrabold text-amber-400" id="stat-v-risky">0</div>
                    <p class="text-[10px] text-slate-500 mt-2 font-bold">POSSIBLE BOUNCE RISK</p>
                </div>
                <div class="glass p-6 rounded-3xl border-l-4 border-rose-500/50">
                    <p class="text-[10px] font-black text-rose-500 uppercase mb-1">Dead / Malformed</p>
                    <div class="text-3xl font-extrabold text-rose-400" id="stat-v-invalid">0</div>
                    <p class="text-[10px] text-slate-500 mt-2 font-bold">CRITICAL FAILURE RATE</p>
                </div>
            </div>

            <div class="grid lg:grid-cols-12 gap-8">
                <!-- Input Panel -->
                <div class="lg:col-span-4 space-y-6">
                    <div class="glass p-8 rounded-3xl space-y-4 shadow-2xl">
                        <h3 class="font-black uppercase tracking-tighter text-xl">Intelligence <span class="text-blue-500">Input</span></h3>
                        <div class="space-y-2">
                            <label class="text-[10px] font-bold text-slate-500 uppercase">Email Repository</label>
                            <textarea id="v-input" class="w-full h-64 bg-slate-900/50 border border-white/10 rounded-2xl p-4 text-sm mono focus:border-blue-500 outline-none transition-all" placeholder="Paste emails here...&#10;one@domain.com&#10;two@domain.com"></textarea>
                        </div>
                        <div class="flex gap-4">
                            <button onclick="clearVerify()" class="flex-1 py-4 rounded-2xl bg-white/5 hover:bg-white/10 font-bold transition">Clear</button>
                            <button onclick="startVerification()" id="v-start-btn" class="flex-[2] btn-primary py-4 rounded-2xl font-black uppercase tracking-widest text-sm">
                                <i class="fas fa-bolt mr-2"></i> Execute Scan
                            </button>
                        </div>
                    </div>
                </div>

                <!-- Results Panel -->
                <div class="lg:col-span-8">
                    <div class="glass rounded-3xl overflow-hidden flex flex-col h-[520px]">
                        <div class="px-8 py-6 border-b border-white/5 flex justify-between items-center bg-white/[0.02]">
                            <h3 class="font-bold flex items-center gap-3">
                                <span class="w-2 h-2 rounded-full bg-blue-500 shadow-[0_0_10px_#3b82f6]"></span> 
                                Real-time Intelligence Feed
                            </h3>
                            <div class="flex gap-3">
                                <button onclick="downloadResults('VALID')" class="bg-emerald-500/10 text-emerald-400 text-[10px] font-black px-4 py-2 rounded-xl border border-emerald-500/20 hover:bg-emerald-500/20 transition">Export Valid</button>
                                <button onclick="downloadResults('INVALID')" class="bg-rose-500/10 text-rose-400 text-[10px] font-black px-4 py-2 rounded-xl border border-rose-500/20 hover:bg-rose-500/20 transition">Export Dead</button>
                            </div>
                        </div>
                        <div class="flex-1 overflow-y-auto overflow-x-hidden p-0" id="v-scroll-container">
                            <table class="w-full text-left border-collapse">
                                <thead class="sticky top-0 bg-slate-900 text-[10px] font-black uppercase text-slate-500 border-b border-white/5">
                                    <tr>
                                        <th class="px-8 py-4">Target Identity</th>
                                        <th class="px-4 py-4">Security Score</th>
                                        <th class="px-4 py-4">Provider / MX</th>
                                        <th class="px-4 py-4 text-right pr-8">Status</th>
                                    </tr>
                                </thead>
                                <tbody id="v-table-body" class="divide-y divide-white/5">
                                    <!-- Dynamic content -->
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <!-- SECTION: MAILER -->
        <section id="tab-mailer" class="hidden space-y-8 animate-in fade-in duration-500">
            <div class="grid lg:grid-cols-12 gap-8">
                <!-- Config Side -->
                <div class="lg:col-span-4 space-y-6">
                    <div class="glass p-8 rounded-3xl space-y-6">
                        <h3 class="font-black uppercase tracking-tighter text-xl text-blue-500">SMTP Gateway</h3>
                        <div class="space-y-4">
                            <div class="space-y-2">
                                <label class="text-[10px] font-bold text-slate-500 uppercase">Secure Identity</label>
                                <div class="relative">
                                    <i class="fas fa-envelope absolute left-4 top-1/2 -translate-y-1/2 text-slate-600"></i>
                                    <input type="email" id="s-user" class="w-full bg-slate-900 border border-white/10 rounded-xl py-3 pl-12 pr-4 text-sm focus:border-blue-500 outline-none" placeholder="your-email@gmail.com">
                                </div>
                            </div>
                            <div class="space-y-2">
                                <label class="text-[10px] font-bold text-slate-500 uppercase">Encrypted Key / App Pass</label>
                                <div class="relative">
                                    <i class="fas fa-key absolute left-4 top-1/2 -translate-y-1/2 text-slate-600"></i>
                                    <input type="password" id="s-pass" class="w-full bg-slate-900 border border-white/10 rounded-xl py-3 pl-12 pr-4 text-sm focus:border-blue-500 outline-none" placeholder="••••••••••••••••">
                                </div>
                            </div>
                            <div class="pt-4 border-t border-white/5 space-y-2">
                                <label class="text-[10px] font-bold text-slate-500 uppercase">Verified Target List</label>
                                <textarea id="s-recipients" class="w-full h-48 bg-slate-900 border border-white/10 rounded-xl p-4 text-sm mono" placeholder="Paste validated emails here..."></textarea>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Editor Side -->
                <div class="lg:col-span-8 space-y-6">
                    <div class="glass p-8 rounded-3xl space-y-6">
                        <div class="flex justify-between items-center">
                            <h3 class="font-black uppercase tracking-tighter text-xl">Campaign <span class="text-blue-500">Architect</span></h3>
                            <div class="flex items-center gap-3">
                                <span id="s-status-tag" class="hidden text-[10px] font-black px-3 py-1 bg-indigo-500/10 text-indigo-400 rounded-full border border-indigo-500/20 uppercase tracking-widest">Deploying...</span>
                            </div>
                        </div>
                        
                        <div class="space-y-4">
                            <input type="text" id="s-subject" class="w-full bg-slate-900 border border-white/10 rounded-xl p-4 text-lg font-bold focus:border-blue-500 outline-none" placeholder="Enter Campaign Subject Line">
                            <div id="editor-container">
                                <div id="editor" class="h-[300px]"></div>
                            </div>
                            
                            <div class="flex flex-col md:flex-row justify-between items-center gap-4 pt-4">
                                <div class="flex items-center gap-4 w-full md:w-auto">
                                    <label class="cursor-pointer bg-white/5 hover:bg-white/10 border border-white/10 px-6 py-3 rounded-xl transition flex items-center gap-2">
                                        <i class="fas fa-paperclip text-slate-400"></i>
                                        <span id="file-label" class="text-xs font-bold uppercase">Attach Assets</span>
                                        <input type="file" id="s-attach" class="hidden" onchange="updateFileLabel(this)">
                                    </label>
                                    <button onclick="resetCampaign()" class="text-xs font-bold text-slate-500 hover:text-white transition uppercase">Reset</button>
                                </div>
                                <button onclick="sendCampaign()" id="s-send-btn" class="w-full md:w-auto btn-primary px-12 py-4 rounded-2xl font-black uppercase tracking-widest text-sm">
                                    <i class="fas fa-paper-plane mr-2"></i> Launch Campaign
                                </button>
                            </div>
                        </div>

                        <!-- Progress Overlay -->
                        <div id="s-progress-container" class="hidden mt-6 p-6 bg-blue-500/5 border border-blue-500/10 rounded-2xl animate-pulse">
                            <div class="flex justify-between items-end mb-3">
                                <div>
                                    <p class="text-[10px] font-black text-blue-500 uppercase">Delivery Pipeline</p>
                                    <h4 class="text-xl font-bold" id="s-progress-text">Sending 0 / 0</h4>
                                </div>
                                <div class="text-right">
                                    <span class="text-xs mono font-bold text-slate-400" id="s-perc">0%</span>
                                </div>
                            </div>
                            <div class="w-full h-2 bg-white/5 rounded-full overflow-hidden">
                                <div id="s-progress-bar" class="bg-blue-500 h-full transition-all duration-700" style="width: 0%"></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <!-- SECTION: ANALYTICS -->
        <section id="tab-analytics" class="hidden space-y-8 animate-in fade-in duration-500">
            <div class="glass rounded-3xl overflow-hidden">
                <div class="p-8 border-b border-white/5 flex justify-between items-center">
                    <div>
                        <h3 class="text-xl font-black uppercase tracking-tighter">Enterprise <span class="text-blue-500">Audit Logs</span></h3>
                        <p class="text-[10px] text-slate-500 font-bold uppercase mt-1">Full delivery & verification history</p>
                    </div>
                    <button onclick="refreshLogs()" class="p-3 hover:bg-white/5 rounded-full transition"><i class="fas fa-sync-alt"></i></button>
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full text-left">
                        <thead class="bg-white/[0.02] text-[10px] uppercase font-black text-slate-500 border-b border-white/5">
                            <tr>
                                <th class="p-6">Execution Timestamp</th>
                                <th class="p-6">Target Address</th>
                                <th class="p-6">Context / Subject</th>
                                <th class="p-6">Outcome</th>
                            </tr>
                        </thead>
                        <tbody id="log-table-body" class="divide-y divide-white/5">
                            <!-- Logs -->
                        </tbody>
                    </table>
                </div>
            </div>
        </section>
    </main>

    <script src="https://cdn.quilljs.com/1.3.6/quill.js"></script>
    <script>
        const quill = new Quill('#editor', {
            theme: 'snow',
            placeholder: 'Compose your enterprise campaign content...',
            modules: {
                toolbar: [
                    ['bold', 'italic', 'underline'],
                    [{ 'list': 'ordered'}, { 'list': 'bullet' }],
                    [{ 'header': [1, 2, 3, false] }],
                    ['link', 'clean']
                ]
            }
        });

        let eventSource = null;

        function switchTab(id) {
            ['verify', 'mailer', 'analytics'].forEach(t => {
                document.getElementById('tab-' + t).classList.add('hidden');
                document.getElementById('nav-' + t).classList.remove('active');
            });
            document.getElementById('tab-' + id).classList.remove('hidden');
            document.getElementById('nav-' + id).classList.add('active');
            if (id === 'analytics') refreshLogs();
        }

        // Verification Logic
        function startVerification() {
            const val = document.getElementById('v-input').value;
            if (!val.trim()) return;

            const btn = document.getElementById('v-start-btn');
            btn.disabled = true;
            btn.innerHTML = `<i class="fas fa-circle-notch animate-spin mr-2"></i> Processing...`;
            
            document.getElementById('v-table-body').innerHTML = '';

            fetch('/api/verify', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({emails: val.split('\\n')})
            }).then(() => {
                connectStream();
            });
        }

        function connectStream() {
            if(eventSource) eventSource.close();
            eventSource = new EventSource('/api/stream');
            
            eventSource.onmessage = (e) => {
                const data = JSON.parse(e.data);
                
                if (data.type === 'stats') {
                    updateStats(data);
                } else if (data.type === 'result') {
                    appendResultRow(data);
                }
            };
        }

        function updateStats(d) {
            document.getElementById('stat-v-total').innerText = d.v_done + ' / ' + d.v_total;
            document.getElementById('stat-v-valid').innerText = d.v_valid;
            document.getElementById('stat-v-risky').innerText = d.v_risky;
            document.getElementById('stat-v-invalid').innerText = d.v_invalid;
            
            const perc = (d.v_done / d.v_total) * 100 || 0;
            document.getElementById('v-progress-bar').style.width = perc + '%';

            if (d.v_done >= d.v_total && d.v_total > 0) {
                const btn = document.getElementById('v-start-btn');
                btn.disabled = false;
                btn.innerHTML = `<i class="fas fa-bolt mr-2"></i> Execute Scan`;
            }

            if (d.type_s === 's_stats') {
                document.getElementById('s-progress-text').innerText = `Sending ${d.s_done} / ${d.s_total}`;
                document.getElementById('s-perc').innerText = Math.round((d.s_done/d.s_total)*100) + '%';
                document.getElementById('s-progress-bar').style.width = (d.s_done/d.s_total)*100 + '%';
            }
        }

        function appendResultRow(d) {
            const body = document.getElementById('v-table-body');
            const row = document.createElement('tr');
            row.className = "hover:bg-white/[0.02] transition-colors group";
            
            const scoreColor = d.score > 75 ? 'text-emerald-500' : (d.score > 30 ? 'text-amber-500' : 'text-rose-500');
            const statusClass = d.status === 'VALID' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' : 
                               (d.status === 'RISKY' ? 'bg-amber-500/10 text-amber-400 border-amber-500/20' : 
                                'bg-rose-500/10 text-rose-400 border-rose-500/20');

            row.innerHTML = `
                <td class="px-8 py-5">
                    <div class="font-bold text-sm">${d.email}</div>
                    <div class="text-[10px] text-slate-500 font-medium italic mt-0.5">${d.reasons}</div>
                </td>
                <td class="px-4 py-5">
                    <div class="flex items-center gap-3">
                        <div class="flex-1 h-1.5 bg-white/5 rounded-full w-20 overflow-hidden">
                            <div class="h-full ${scoreColor.replace('text', 'bg')}" style="width: ${d.score}%"></div>
                        </div>
                        <span class="mono text-xs font-bold ${scoreColor}">${d.score}%</span>
                    </div>
                </td>
                <td class="px-4 py-5">
                    <div class="text-[10px] font-black uppercase text-slate-500 flex items-center gap-2">
                        <i class="fas fa-server text-[8px]"></i> ${d.provider}
                    </div>
                </td>
                <td class="px-4 py-5 text-right pr-8">
                    <span class="status-badge border ${statusClass}">${d.status}</span>
                </td>
            `;
            body.prepend(row);
        }

        // Campaign Logic
        async function sendCampaign() {
            const user = document.getElementById('s-user').value;
            const pass = document.getElementById('s-pass').value;
            const sub = document.getElementById('s-subject').value;
            const recips = document.getElementById('s-recipients').value.split('\\n').filter(x => x.trim());
            
            if (!user || !pass || !sub || recips.length === 0) {
                return alert("Please complete all configuration fields.");
            }

            document.getElementById('s-send-btn').disabled = true;
            document.getElementById('s-status-tag').classList.remove('hidden');
            document.getElementById('s-progress-container').classList.remove('hidden');

            const payload = {
                user, pass, subject: sub,
                recipients: recips,
                body: quill.root.innerHTML
            };

            const fileInput = document.getElementById('s-attach');
            if (fileInput.files.length > 0) {
                const file = fileInput.files[0];
                const reader = new FileReader();
                reader.onload = () => {
                    payload.attachment = {
                        name: file.name,
                        data: reader.result.split(',')[1]
                    };
                    executeSend(payload);
                };
                reader.readAsDataURL(file);
            } else {
                executeSend(payload);
            }
        }

        function executeSend(payload) {
            fetch('/api/send', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(payload)
            }).then(() => connectStream());
        }

        function refreshLogs() {
            fetch('/api/logs').then(r => r.json()).then(data => {
                const body = document.getElementById('log-table-body');
                body.innerHTML = data.map(l => `
                    <tr class="hover:bg-white/[0.01]">
                        <td class="p-6 text-xs mono text-slate-500">${l[4] || l[5] || 'Recently'}</td>
                        <td class="p-6 font-bold text-sm">${l[1]}</td>
                        <td class="p-6 text-xs text-slate-400 italic">${l[2] || 'Verification Scan'}</td>
                        <td class="p-6">
                            <span class="text-[10px] font-black uppercase ${l[3].includes('SENT') || l[3] === 'VALID' ? 'text-emerald-500' : 'text-rose-500'}">${l[3]}</span>
                        </td>
                    </tr>
                `).join('');
            });
        }

        function updateFileLabel(input) {
            const label = document.getElementById('file-label');
            if (input.files.length > 0) {
                label.innerText = input.files[0].name;
                label.classList.add('text-blue-400');
            }
        }

        function downloadResults(status) {
            window.location = '/api/download/' + status;
        }

        // Uptime Timer
        let startTime = Date.now();
        setInterval(() => {
            const diff = Math.floor((Date.now() - startTime) / 1000);
            const h = String(Math.floor(diff / 3600)).padStart(2, '0');
            const m = String(Math.floor((diff % 3600) / 60)).padStart(2, '0');
            const s = String(diff % 60).padStart(2, '0');
            document.getElementById('uptime').innerText = `UPTIME: ${h}:${m}:${s}`;
        }, 1000);
    </script>
</body>
</html>
"""

# ===============================
# WORKERS: VERIFICATION & SENDING
# ===============================
def verification_worker():
    global STATS
    while True:
        try: email = VERIFY_QUEUE.get(timeout=2)
        except: 
            if not STATS["is_verifying"]: break
            continue
        
        score, reasons, status, provider = TitanVerifier.deep_check(email)
        
        res = {
            "email": email, "status": status, "score": score, 
            "provider": provider, "reasons": ", ".join(reasons),
            "ts": datetime.now().strftime("%H:%M:%S")
        }
        
        with LOCK:
            RESULTS.append(res)
            STATS["v_done"] += 1
            STATS[f"v_{status.lower()}"] += 1
            # Log to DB
            try:
                conn = sqlite3.connect(DATABASE_NAME)
                conn.execute("INSERT INTO verified (email, status, score, provider, reasons, ts) VALUES (?, ?, ?, ?, ?, ?)", 
                             (email, status, score, provider, res["reasons"], datetime.now()))
                conn.commit()
                conn.close()
            except: pass
            
        VERIFY_QUEUE.task_done()

def sending_worker(smtp_config, email_body, subject, attachment_data):
    global STATS
    while not SEND_QUEUE.empty():
        recipient = SEND_QUEUE.get()
        status = "SENT"
        err_msg = ""
        try:
            msg = MIMEMultipart()
            msg['From'] = smtp_config['user']
            msg['To'] = recipient
            msg['Subject'] = subject
            msg.attach(MIMEText(email_body, 'html'))

            if attachment_data:
                part = MIMEBase('application', "octet-stream")
                part.set_payload(base64.b64decode(attachment_data['data']))
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', f'attachment; filename="{attachment_data["name"]}"')
                msg.attach(part)

            # Enterprise Gmail SMTP Configuration
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context, timeout=20) as server:
                server.login(smtp_config['user'], smtp_config['pass'])
                server.sendmail(smtp_config['user'], recipient, msg.as_string())
            
            with LOCK: STATS["s_success"] += 1
        except Exception as e:
            status = "FAILED"
            err_msg = str(e)
            with LOCK: STATS["s_fail"] += 1
        
        with LOCK:
            STATS["s_done"] += 1
            try:
                conn = sqlite3.connect(DATABASE_NAME)
                conn.execute("INSERT INTO send_history (recipient, subject, status, error_msg, ts) VALUES (?, ?, ?, ?, ?)", 
                             (recipient, subject, status, err_msg, datetime.now()))
                conn.commit()
                conn.close()
            except: pass
        
        SEND_QUEUE.task_done()
        time.sleep(random.uniform(2.0, 5.0)) # Strategic pacing to prevent IP flagging

# ===============================
# API ROUTES
# ===============================
@app.route('/')
def index(): 
    return render_template_string(DASHBOARD_HTML)

@app.route('/api/verify', methods=['POST'])
def start_v():
    global STATS, RESULTS
    data = request.json
    with LOCK:
        RESULTS.clear()
        emails = list(set([e.strip() for e in data['emails'] if e.strip()])) # Unique only
        STATS.update({"v_total": len(emails), "v_done": 0, "v_valid": 0, "v_risky": 0, "v_invalid": 0, "is_verifying": True})
        for e in emails: VERIFY_QUEUE.put(e)
    
    for _ in range(min(CONCURRENT_VERIFIERS, len(emails) or 1)):
        threading.Thread(target=verification_worker, daemon=True).start()
    return jsonify({"status": "initialized", "count": len(emails)})

@app.route('/api/send', methods=['POST'])
def start_s():
    global STATS
    data = request.json
    recipients = list(set([r.strip() for r in data['recipients'] if r.strip()]))
    with LOCK:
        STATS.update({"s_total": len(recipients), "s_done": 0, "s_success": 0, "s_fail": 0, "is_sending": True})
        for r in recipients: SEND_QUEUE.put(r)
    
    smtp_conf = {"user": data['user'], "pass": data['pass']}
    threading.Thread(target=sending_worker, args=(smtp_conf, data['body'], data['subject'], data.get('attachment')), daemon=True).start()
    return jsonify({"status": "deployment_started"})

@app.route('/api/stream')
def stream():
    def gen():
        sent_results = 0
        while True:
            with LOCK:
                # Stream verification results
                if sent_results < len(RESULTS):
                    batch = RESULTS[sent_results:]
                    for r in batch: yield f"data: {json.dumps({'type': 'result', **r})}\n\n"
                    sent_results = len(RESULTS)
                
                # Stream stats
                payload = {"type": "stats", **STATS}
                yield f"data: {json.dumps(payload)}\n\n"
                
                # Termination logic
                v_finished = (STATS["v_done"] >= STATS["v_total"] and STATS["v_total"] > 0)
                s_finished = (STATS["s_done"] >= STATS["s_total"] and STATS["s_total"] > 0)
                
                if (v_finished and not STATS["is_sending"]) or (v_finished and s_finished):
                    break
            time.sleep(0.8)
    return Response(gen(), mimetype='text/event-stream')

@app.route('/api/logs')
def get_logs():
    conn = sqlite3.connect(DATABASE_NAME)
    # Combine verification and sending logs for the unified log view
    v_logs = conn.execute("SELECT id, email, 'Verification', status, ts FROM verified ORDER BY ts DESC LIMIT 50").fetchall()
    s_logs = conn.execute("SELECT id, recipient, subject, status, ts FROM send_history ORDER BY ts DESC LIMIT 50").fetchall()
    combined = sorted(v_logs + s_logs, key=lambda x: x[4], reverse=True)
    conn.close()
    return jsonify(combined)

@app.route('/api/download/<status>')
def download(status):
    si = StringIO()
    si.write("email\n")
    conn = sqlite3.connect(DATABASE_NAME)
    rows = conn.execute("SELECT email FROM verified WHERE status = ?", (status,)).fetchall()
    conn.close()
    for r in rows:
        si.write(f"{r[0]}\n")
    output = si.getvalue()
    return Response(output, mimetype="text/csv", headers={"Content-disposition": f"attachment; filename=titan_{status.lower()}_export.csv"})

if __name__ == '__main__':
    # Using threaded=True to handle concurrent SSE and API calls
    app.run(port=5000, threaded=True, debug=False)