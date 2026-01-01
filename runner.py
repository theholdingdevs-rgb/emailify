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
from datetime import datetime
from io import StringIO

import dns.resolver
from flask import Flask, request, Response, render_template_string, send_file, jsonify

# ===============================
# ENTERPRISE CONFIGURATION
# ===============================
app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

DATABASE_NAME = "enterprise_verifier.db"
SMTP_TIMEOUT = 12
CONCURRENT_THREADS = 15  # Scalable for local use
HELO_HOST = "mail.enterprise-local.com"
MAIL_FROM = "verify@enterprise-local.com"

# Regex for strict RFC 5322 compliance checking
EMAIL_REGEX = re.compile(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")

# Risk Factor Data
ROLE_PREFIXES = {
    "admin", "info", "support", "sales", "contact", "help", "career", "billing", 
    "accounts", "abuse", "postmaster", "hr", "webmaster", "marketing", "no-reply"
}

# Extensive disposable list (sample - in production this would be thousands)
DISPOSABLE_DOMAINS = {
    "mailinator.com", "tempmail.com", "10minutemail.com", "guerrillamail.com", 
    "yopmail.com", "dispostable.com", "getnada.com", "maildrop.cc", "trashmail.com"
}

# Major Provider MX keywords
PROVIDER_KEYWORDS = {
    "google": ["google.com", "googlemail.com", "aspmx.l.google.com"],
    "microsoft": ["outlook.com", "hotmail.com", "messaging.microsoft.com"],
    "yahoo": ["yahoodns.net", "yahoo.com"],
    "apple": ["icloud.com", "me.com", "apple.com"],
    "zoho": ["zoho.com"]
}

# ===============================
# STATE MANAGEMENT
# ===============================
TASK_QUEUE = queue.Queue()
RESULTS_LOG = []
STATS = {
    "total": 0,
    "processed": 0,
    "valid": 0,
    "risky": 0,
    "invalid": 0,
    "start_time": None,
    "is_running": False
}
RESULTS_LOCK = threading.Lock()

# ===============================
# DATABASE INITIALIZATION
# ===============================
def init_db():
    conn = sqlite3.connect(DATABASE_NAME)
    c = conn.cursor()
    # Store domain reputation to speed up repeat scans
    c.execute("""
        CREATE TABLE IF NOT EXISTS domain_cache (
            domain TEXT PRIMARY KEY,
            mx_records TEXT,
            is_catchall INTEGER,
            is_disposable INTEGER,
            provider TEXT,
            last_updated TIMESTAMP
        )
    """)
    # Log individual verifications for historical analysis
    c.execute("""
        CREATE TABLE IF NOT EXISTS verification_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT,
            status TEXT,
            risk_score INTEGER,
            timestamp DATETIME
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ===============================
# ANALYTICS & LOGIC ENGINE
# ===============================

class VerificationEngine:
    @staticmethod
    def get_mx_records(domain):
        try:
            records = dns.resolver.resolve(domain, 'MX')
            mx_list = sorted([(r.preference, r.exchange.to_text().rstrip('.')) for r in records])
            return [m[1] for m in mx_list]
        except Exception:
            try:
                # Fallback to A record if no MX
                dns.resolver.resolve(domain, 'A')
                return [domain]
            except:
                return []

    @staticmethod
    def probe_smtp(mx_host, target_email):
        """
        Deep SMTP Probe: Attempts to simulate a mail send without actually sending.
        """
        try:
            with smtplib.SMTP(mx_host, timeout=SMTP_TIMEOUT) as server:
                server.set_debuglevel(0)
                server.helo(HELO_HOST)
                server.mail(MAIL_FROM)
                code, message = server.rcpt(target_email)
                return code, message.decode('utf-8', errors='ignore')
        except socket.timeout:
            return 408, "Connection Timeout"
        except Exception as e:
            return 500, str(e)

    @staticmethod
    def check_catchall(mx_host, domain):
        """Checks if the server accepts any random email address."""
        random_prefix = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=12))
        test_email = f"{random_prefix}@{domain}"
        code, _ = VerificationEngine.probe_smtp(mx_host, test_email)
        return code == 250

    @staticmethod
    def identify_provider(mx_records):
        mx_str = " ".join(mx_records).lower()
        for provider, keywords in PROVIDER_KEYWORDS.items():
            if any(k in mx_str for k in keywords):
                return provider
        return "independent"

    @staticmethod
    def calculate_risk(email, dns_data, smtp_code, provider, is_catchall):
        score = 50  # Base Neutral
        reasons = []

        # Syntax is assumed OK to get here
        prefix = email.split('@')[0].lower()
        domain = email.split('@')[1].lower()

        # Rule: DNS Status
        if not dns_data:
            return 0, ["No MX or A records found"]
        
        score += 15
        
        # Rule: SMTP Response
        if smtp_code == 250:
            score += 25
        elif smtp_code in [550, 551, 553, 554]:
            return 0, [f"SMTP Rejected: {smtp_code}"]
        else:
            score -= 10
            reasons.append("SMTP probe inconclusive")

        # Rule: Role Based
        if prefix in ROLE_PREFIXES:
            score -= 15
            reasons.append("Role-based account")

        # Rule: Disposable
        if domain in DISPOSABLE_DOMAINS:
            score -= 40
            reasons.append("Disposable/Temporary provider")

        # Rule: Catch-all
        if is_catchall:
            score -= 20
            reasons.append("Catch-all domain detected")

        # Rule: Provider Reputation
        if provider in ["google", "microsoft"]:
            score += 5  # High trust providers

        final_score = max(0, min(100, score))
        return final_score, reasons

# ===============================
# WORKER THREAD LOGIC
# ===============================

def worker_process():
    global STATS
    while STATS["is_running"]:
        try:
            email = TASK_QUEUE.get(timeout=2)
        except queue.Empty:
            if STATS["processed"] >= STATS["total"]:
                break
            continue

        domain = email.split('@')[1].lower()
        
        # 1. DNS Logic
        mxs = VerificationEngine.get_mx_records(domain)
        dns_status = "OK" if mxs else "FAIL"
        
        # 2. SMTP & Catchall Logic
        smtp_code = None
        is_catchall = False
        provider = "unknown"
        
        if mxs:
            provider = VerificationEngine.identify_provider(mxs)
            # We use the primary MX
            smtp_code, _ = VerificationEngine.probe_smtp(mxs[0], email)
            is_catchall = VerificationEngine.check_catchall(mxs[0], domain)

        # 3. Risk Calculation
        risk_score, reasons = VerificationEngine.calculate_risk(
            email, mxs, smtp_code, provider, is_catchall
        )

        # 4. Final Classification
        if risk_score >= 75:
            status = "VALID"
        elif risk_score >= 35:
            status = "RISKY"
        else:
            status = "INVALID"

        result_item = {
            "email": email,
            "status": status,
            "score": risk_score,
            "provider": provider,
            "dns": dns_status,
            "smtp": str(smtp_code) if smtp_code else "N/A",
            "catchall": "YES" if is_catchall else "NO",
            "reasons": ", ".join(reasons) if reasons else "Clean",
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

        with RESULTS_LOCK:
            RESULTS_LOG.append(result_item)
            STATS["processed"] += 1
            STATS[status.lower()] += 1
            
            # Persistent Log
            try:
                conn = sqlite3.connect(DATABASE_NAME)
                c = conn.cursor()
                c.execute("INSERT INTO verification_history (email, status, risk_score, timestamp) VALUES (?, ?, ?, ?)",
                          (email, status, risk_score, datetime.now()))
                conn.commit()
                conn.close()
            except: pass

        TASK_QUEUE.task_done()
        # Polite delay to prevent local IP blacklisting
        time.sleep(random.uniform(0.1, 0.3))

# ===============================
# MODERN UI COMPONENTS (REACT + TAILWIND)
# ===============================

HTML_DASHBOARD = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enterprise Email Validator Pro</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Plus Jakarta Sans', sans-serif; background-color: #0b0f1a; color: #f8fafc; }
        .glass { background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(12px); border: 1px solid rgba(255,255,255,0.05); }
        .status-valid { color: #10b981; background: rgba(16, 185, 129, 0.1); }
        .status-risky { color: #f59e0b; background: rgba(245, 158, 11, 0.1); }
        .status-invalid { color: #ef4444; background: rgba(239, 68, 68, 0.1); }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: #0f172a; }
        ::-webkit-scrollbar-thumb { background: #334155; border-radius: 10px; }
        .shimmer { background: linear-gradient(90deg, #22d3ee, #818cf8); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    </style>
</head>
<body class="p-4 lg:p-8">
    <div class="max-w-7xl mx-auto">
        <!-- Header -->
        <div class="flex flex-col md:flex-row justify-between items-start md:items-center mb-8 gap-4">
            <div>
                <h1 class="text-3xl font-extrabold tracking-tight shimmer">Enterprise Email Engine</h1>
                <p class="text-slate-400 text-sm mt-1">Local SMTP Probing • DNS Validation • Multi-Threaded Heuristics</p>
            </div>
            <div class="flex gap-3">
                <input type="file" id="csvFile" class="hidden" accept=".txt,.csv">
                <button onclick="document.getElementById('csvFile').click()" class="bg-slate-800 hover:bg-slate-700 px-5 py-2.5 rounded-xl font-semibold transition text-sm border border-slate-700">
                    Upload List
                </button>
                <button id="startBtn" onclick="startVerification()" class="bg-cyan-500 hover:bg-cyan-400 text-slate-900 px-6 py-2.5 rounded-xl font-bold transition text-sm shadow-lg shadow-cyan-500/20">
                    Run Engine
                </button>
            </div>
        </div>

        <!-- Stats Grid -->
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
            <div class="glass p-5 rounded-2xl">
                <p class="text-slate-400 text-xs font-bold uppercase tracking-wider mb-1">Total Loaded</p>
                <h2 id="stat-total" class="text-3xl font-bold">0</h2>
            </div>
            <div class="glass p-5 rounded-2xl border-l-4 border-emerald-500">
                <p class="text-emerald-400 text-xs font-bold uppercase tracking-wider mb-1">Valid</p>
                <h2 id="stat-valid" class="text-3xl font-bold text-emerald-400">0</h2>
            </div>
            <div class="glass p-5 rounded-2xl border-l-4 border-amber-500">
                <p class="text-amber-400 text-xs font-bold uppercase tracking-wider mb-1">Risky</p>
                <h2 id="stat-risky" class="text-3xl font-bold text-amber-400">0</h2>
            </div>
            <div class="glass p-5 rounded-2xl border-l-4 border-rose-500">
                <p class="text-rose-400 text-xs font-bold uppercase tracking-wider mb-1">Invalid</p>
                <h2 id="stat-invalid" class="text-3xl font-bold text-rose-400">0</h2>
            </div>
        </div>

        <!-- Progress Bar -->
        <div class="glass p-6 rounded-2xl mb-8">
            <div class="flex justify-between mb-4 items-center">
                <span id="progress-text" class="text-sm font-medium text-slate-300">Awaiting file upload...</span>
                <span id="progress-percent" class="text-sm font-bold text-cyan-400">0%</span>
            </div>
            <div class="w-full bg-slate-900 rounded-full h-3 overflow-hidden">
                <div id="progress-bar" class="bg-gradient-to-r from-cyan-500 to-indigo-500 h-full transition-all duration-500" style="width: 0%"></div>
            </div>
        </div>

        <!-- Main Layout -->
        <div class="grid lg:grid-cols-3 gap-8">
            <!-- Feed Table -->
            <div class="lg:col-span-2 glass rounded-2xl overflow-hidden flex flex-col h-[600px]">
                <div class="p-4 border-b border-white/5 flex justify-between items-center bg-white/5">
                    <h3 class="font-bold text-sm">Live Verification Stream</h3>
                    <div class="flex gap-2">
                         <div class="h-2 w-2 rounded-full bg-red-500 animate-pulse"></div>
                         <span class="text-[10px] uppercase font-black text-slate-500 tracking-widest">Realtime Feed</span>
                    </div>
                </div>
                <div class="overflow-y-auto flex-1 p-0">
                    <table class="w-full text-left border-collapse">
                        <thead class="sticky top-0 bg-slate-800 text-[11px] uppercase text-slate-400 font-bold z-10">
                            <tr>
                                <th class="p-4 border-b border-white/5">Email Address</th>
                                <th class="p-4 border-b border-white/5">Status</th>
                                <th class="p-4 border-b border-white/5 text-center">Score</th>
                                <th class="p-4 border-b border-white/5">Provider</th>
                                <th class="p-4 border-b border-white/5">SMTP</th>
                            </tr>
                        </thead>
                        <tbody id="result-rows">
                            <!-- Rows injected here -->
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Export & Details -->
            <div class="flex flex-col gap-6">
                <div class="glass p-6 rounded-2xl">
                    <h3 class="font-bold mb-4 text-sm text-slate-300 uppercase tracking-widest">Secure Export</h3>
                    <div class="grid grid-cols-1 gap-3">
                        <button onclick="downloadResults('VALID')" class="w-full py-3 px-4 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 rounded-xl font-bold text-xs transition flex justify-between items-center">
                            Download Verified Valid <span>CSV</span>
                        </button>
                        <button onclick="downloadResults('RISKY')" class="w-full py-3 px-4 bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 border border-amber-500/30 rounded-xl font-bold text-xs transition flex justify-between items-center">
                            Download Risky Contacts <span>CSV</span>
                        </button>
                        <button onclick="downloadResults('INVALID')" class="w-full py-3 px-4 bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 rounded-xl font-bold text-xs transition flex justify-between items-center">
                            Download Invalid List <span>CSV</span>
                        </button>
                    </div>
                </div>

                <div class="glass p-6 rounded-2xl flex-1">
                    <h3 class="font-bold mb-4 text-sm text-slate-300 uppercase tracking-widest">Engine Diagnostics</h3>
                    <div id="diagnostics" class="space-y-4 text-xs">
                        <div class="flex justify-between py-2 border-b border-white/5">
                            <span class="text-slate-500">Threads Engaged</span>
                            <span class="text-cyan-400 font-mono">15 Parallel</span>
                        </div>
                        <div class="flex justify-between py-2 border-b border-white/5">
                            <span class="text-slate-500">Heuristic Depth</span>
                            <span class="text-slate-300 font-mono">RFC + DNS + SMTP</span>
                        </div>
                        <div class="flex justify-between py-2 border-b border-white/5">
                            <span class="text-slate-500">SMTP Timeout</span>
                            <span class="text-slate-300 font-mono">12 Seconds</span>
                        </div>
                         <div class="mt-6 p-4 rounded-xl bg-slate-900 border border-slate-800">
                            <p class="text-slate-400 leading-relaxed italic">
                                "This local engine probes mail servers directly. Ensure your local ISP allows outgoing traffic on port 25/587 for best results."
                            </p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let eventSource = null;

        function startVerification() {
            const fileInput = document.getElementById('csvFile');
            if (!fileInput.files.length) {
                alert("Please select a file first.");
                return;
            }

            const formData = new FormData();
            formData.append('file', fileInput.files[0]);

            document.getElementById('startBtn').disabled = true;
            document.getElementById('startBtn').innerText = "Running...";
            document.getElementById('result-rows').innerHTML = '';

            fetch('/api/start', {
                method: 'POST',
                body: formData
            }).then(() => {
                initStream();
            });
        }

        function initStream() {
            if (eventSource) eventSource.close();
            eventSource = new EventSource('/api/stream');

            eventSource.onmessage = function(e) {
                const data = JSON.parse(e.data);

                if (data.type === 'progress') {
                    document.getElementById('stat-total').innerText = data.total;
                    document.getElementById('stat-valid').innerText = data.valid;
                    document.getElementById('stat-risky').innerText = data.risky;
                    document.getElementById('stat-invalid').innerText = data.invalid;

                    const perc = data.total > 0 ? Math.round((data.processed / data.total) * 100) : 0;
                    document.getElementById('progress-bar').style.width = perc + '%';
                    document.getElementById('progress-percent').innerText = perc + '%';
                    document.getElementById('progress-text').innerText = `Processed ${data.processed} of ${data.total} items...`;
                }

                if (data.type === 'result') {
                    addResultRow(data);
                }

                if (data.done) {
                    eventSource.close();
                    document.getElementById('startBtn').disabled = false;
                    document.getElementById('startBtn').innerText = "Run Engine";
                    document.getElementById('progress-text').innerText = "Verification Complete.";
                }
            };
        }

        function addResultRow(item) {
            const tbody = document.getElementById('result-rows');
            const row = document.createElement('tr');
            row.className = "hover:bg-white/5 transition border-b border-white/5 text-sm";
            
            const statusClass = item.status === 'VALID' ? 'status-valid' : (item.status === 'RISKY' ? 'status-risky' : 'status-invalid');
            
            row.innerHTML = `
                <td class="p-4 font-medium text-slate-200">${item.email}</td>
                <td class="p-4">
                    <span class="px-2 py-1 rounded-md text-[10px] font-bold ${statusClass}">${item.status}</span>
                </td>
                <td class="p-4 text-center font-mono text-slate-400">${item.score}%</td>
                <td class="p-4 text-xs text-slate-500 capitalize">${item.provider}</td>
                <td class="p-4 font-mono text-xs text-slate-500">${item.smtp || 'N/A'}</td>
            `;
            tbody.prepend(row);
        }

        function downloadResults(type) {
            window.location.href = `/api/download/${type}`;
        }
    </script>
</body>
</html>
"""

# ===============================
# FLASK ROUTES
# ===============================

@app.route('/')
def index():
    return render_template_string(HTML_DASHBOARD)

@app.route('/api/start', methods=['POST'])
def start_verification():
    global STATS, RESULTS_LOG, TASK_QUEUE
    
    # Reset State
    with RESULTS_LOCK:
        RESULTS_LOG.clear()
        while not TASK_QUEUE.empty(): TASK_QUEUE.get()
        
        file = request.files['file']
        content = file.read().decode('utf-8', errors='ignore')
        
        emails = []
        for line in content.splitlines():
            clean = line.strip().strip(',').strip('"')
            if EMAIL_REGEX.match(clean):
                emails.append(clean)
        
        STATS.update({
            "total": len(emails),
            "processed": 0,
            "valid": 0,
            "risky": 0,
            "invalid": 0,
            "is_running": True,
            "start_time": time.time()
        })
        
        for email in emails:
            TASK_QUEUE.put(email)

    # Spawn Workers
    for _ in range(CONCURRENT_THREADS):
        threading.Thread(target=worker_process, daemon=True).start()

    return jsonify({"status": "started", "count": len(emails)})

@app.route('/api/stream')
def stream_results():
    def event_stream():
        sent_count = 0
        while True:
            # Send Batch of new results
            with RESULTS_LOCK:
                if sent_count < len(RESULTS_LOG):
                    new_items = RESULTS_LOG[sent_count:]
                    for item in new_items:
                        yield f"data: {json.dumps({'type': 'result', **item})}\n\n"
                    sent_count = len(RESULTS_LOG)
                
                # Send Progress Pulse
                payload = {"type": "progress", **STATS}
                if STATS["total"] > 0 and STATS["processed"] >= STATS["total"]:
                    payload["done"] = True
                    yield f"data: {json.dumps(payload)}\n\n"
                    break
                
                yield f"data: {json.dumps(payload)}\n\n"

            time.sleep(0.5)

    return Response(event_stream(), mimetype='text/event-stream')

@app.route('/api/download/<status>')
def download_data(status):
    output = StringIO()
    output.write("Email,Status,RiskScore,Provider,DNS,SMTP,CatchAll,Reasons\n")
    
    with RESULTS_LOCK:
        for r in RESULTS_LOG:
            if r['status'] == status.upper():
                output.write(f"{r['email']},{r['status']},{r['score']},{r['provider']},{r['dns']},{r['smtp']},{r['catchall']},\"{r['reasons']}\"\n")
    
    output.seek(0)
    return send_file(
        StringIO(output.getvalue()), 
        mimetype="text/csv", 
        as_attachment=True, 
        download_name=f"verifier_{status.lower()}_{datetime.now().strftime('%Y%m%d')}.csv"
    )

if __name__ == '__main__':
    # Threaded mode is required for SSE
    print("--------------------------------------------------")
    print("ENTERPRISE LOCAL EMAIL VERIFIER")
    print("URL: http://127.0.0.1:5000")
    print("--------------------------------------------------")
    app.run(host='127.0.0.1', port=5000, threaded=True, debug=False)