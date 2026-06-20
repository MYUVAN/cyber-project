import os
import json
from datetime import datetime
import logging
import flask.cli

# Suppress Flask development server warning banner
flask.cli.show_server_banner = lambda *x: None

# Suppress only the Werkzeug development server warning while keeping standard logs
class SuppressDevServerWarningFilter(logging.Filter):
    def filter(self, record):
        return "WARNING: This is a development server." not in record.getMessage()

log = logging.getLogger("werkzeug")
log.addFilter(SuppressDevServerWarningFilter())

from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory

# Import modular analysis engines
from modules.static_analysis import analyze_file
from modules.dynamic_analysis import simulate_dynamic_analysis
from modules.ioc_extractor import extract_and_store_iocs
from modules.mitre_mapper import map_and_store_mitre
from modules.risk_engine import calculate_risk_score, get_beginner_explanation
from modules.mitigation_engine import generate_mitigations
from modules.report_generator import generate_pdf_report
from modules.plugin_manager import run_all_plugins
from modules.unified_correlation_engine import correlate_all_sources

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore

app = Flask(__name__)
app.secret_key = "cybersecurity_simulation_secret_key"

# Paths
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Load .env file variables manually if it exists
env_path = os.path.join(BASE_DIR, ".env")
if os.path.exists(env_path):
    with open(env_path, "r") as f:
        for line in f:
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and "=" in stripped:
                key, val = stripped.split("=", 1)
                os.environ[key.strip()] = val.strip()

@app.context_processor
def inject_keys_status():
    return {
        "keys_status": {
            "virustotal": bool(os.environ.get("VIRUSTOTAL_API_KEY")),
            "abuseipdb": bool(os.environ.get("ABUSEIPDB_API_KEY")),
            "malwarebazaar": bool(os.environ.get("MALWAREBAZAAR_API_KEY")),
            "opswat": bool(os.environ.get("OPSWAT_API_KEY"))
        }
    }

DB_DIR = os.path.join(BASE_DIR, "database")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
REPORTS_FOLDER = os.path.join(BASE_DIR, "static", "reports")

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["REPORTS_FOLDER"] = REPORTS_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024 # 16 MB limit (standard)

# Ensure workspace folders exist
os.makedirs(DB_DIR, exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORTS_FOLDER, exist_ok=True)

# Initialize Firebase Admin SDK
if not firebase_admin._apps:
    cred_path = os.path.join(DB_DIR, "firebase-credentials.json")
    if os.path.exists(cred_path):
        cred = credentials.Certificate(cred_path)
        firebase_admin.initialize_app(cred)
    else:
        try:
            firebase_admin.initialize_app()
        except Exception:
            pass

try:
    db = firestore.client()
except Exception as e:
    cred_path = os.path.join(DB_DIR, "firebase-credentials.json")
    raise RuntimeError(
        f"Firebase credentials not found or invalid. Please download the Service Account private key JSON "
        f"file from Firebase Console and save it to: {cred_path}"
    ) from e

def get_db():
    """Returns the Firestore client."""
    return db

def init_db():
    """Initializes the database schema and seeds initial data in Firestore."""
    db = get_db()
    
    # Ensure kamalesh analyst exists
    kam_ref = db.collection("users").document("kamalesh")
    kamalesh_pass = generate_password_hash("Kamalesh@2006")
    kam_ref.set({
        "password": kamalesh_pass,
        "role": "Security Analyst"
    })
        
    # Ensure admin exists
    admin_ref = db.collection("users").document("admin")
    admin_pass = generate_password_hash("admin123")
    admin_ref.set({
        "password": admin_pass,
        "role": "Admin"
    })
        
    # Seed Mock Analysis Records if table is empty
    files_ref = db.collection("uploaded_files").limit(1).get()
    if len(files_ref) == 0:
        seed_mock_data(db, "kamalesh")

def seed_mock_data(db, user_id):
    """Pre-populates database with sample scans to verify charts on first load."""
    mock_samples = [
        {
            "filename": "wannacry_decryptor.exe",
            "hash": "5e883f89a24a1195973410bc31460d2d31408b067f18a514d2e7ff2b32269a2d",
            "upload_date": "2026-06-12 10:15:30",
            "risk_score": 95,
            "risk_level": "Critical",
            "file_size": 3482000,
            "malware_category": "Ransomware",
            "description": "A destructive ransomware threat that encrypts user data, disables recovery tools, and demands payment.",
            "beginner_explanation": "This file is extremely dangerous. It acts like a digital kidnapper, locking all your photos, documents, and files by encrypting them so you can't open them. It then tries to force you to pay money (a ransom) to get them back.",
            "extension": ".exe",
            "behaviors": [
                {"time": "0.1s", "activity": "Process spawned from user temp directory", "category": "Execution", "severity": "Info"},
                {"time": "0.8s", "activity": "Spawning PowerShell to delete system backup shadow copies (vssadmin.exe delete shadows /all /quiet)", "category": "Defense Evasion", "severity": "Critical"},
                {"time": "1.5s", "activity": "Modifying registry run keys for boot persistence (HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run)", "category": "Persistence", "severity": "High"},
                {"time": "2.8s", "activity": "Establishing encrypted SSL network callback to C2 server: 185.220.101.5", "category": "C2 Connection", "severity": "High"},
                {"time": "4.2s", "activity": "Rapid encryption of document files and appending '.crypt' extension", "category": "Impact", "severity": "Critical"}
            ],
            "mitre": [
                ("T1059", "Command and Scripting Interpreter (PowerShell)", "Adversaries may abuse command and scripting interpreters (specifically PowerShell) to execute malicious commands, scripts, and payloads.", "This file uses hidden command-line scripts (PowerShell) to bypass security blocks and run commands without your knowledge."),
                ("T1547", "Boot or Logon Autostart Execution (Registry Run Keys)", "Adversaries may modify startup registry run keys or file locations to achieve automatic execution of payloads when the system boots up or users login.", "This file changes your computer's startup registry settings so it launches automatically every time you turn on your computer."),
                ("T1041", "Exfiltration Over C2 Channel", "Adversaries may steal sensitive user data and exfiltrate it by sending it over an established command and control (C2) network tunnel.", "This file gathers confidential information from your computer and uploads it secretly to an external server run by threat actors."),
                ("T1486", "Data Encrypted for Impact", "Adversaries may encrypt user or system files to render them unusable and disrupt operations, typically accompanied by ransom demands.", "This is a ransomware attack: it locks (encrypts) your photos, spreadsheets, and documents and demands a fee to unlock them.")
            ],
            "iocs": [
                ("IP", "185.220.101.5"),
                ("Domain", "onion-gateway.net"),
                ("URL", "http://onion-gateway.net/handshake")
            ]
        },
        {
            "filename": "browser_passwords.js",
            "hash": "2f9547d6e6a17b07db3d8fcf533d1b329486c9d81d2e1bdf3226315263156291",
            "upload_date": "2026-06-13 14:22:10",
            "risk_score": 78,
            "risk_level": "High",
            "file_size": 24500,
            "malware_category": "Trojan / Credential Stealer",
            "description": "A stealthy information-stealing Trojan targeting sensitive user credentials and local browser data.",
            "beginner_explanation": "This file is a spyware program designed to spy on you. It silently searches your computer for usernames, passwords, and bank card information saved in your internet browsers. It then tries to send this private information to a cybercriminal.",
            "extension": ".js",
            "behaviors": [
                {"time": "0.1s", "activity": "Process executed with administrative privileges", "category": "Execution", "severity": "Info"},
                {"time": "0.6s", "activity": "Accessing Google Chrome User Data folder: Chrome\\User Data\\Default\\Login Data", "category": "Credential Access", "severity": "Critical"},
                {"time": "1.9s", "activity": "Injecting code into standard svchost.exe system process", "category": "Defense Evasion", "severity": "High"},
                {"time": "2.6s", "activity": "Establishing connection to exfiltration server: fast-downloads.ru", "category": "C2 Connection", "severity": "High"},
                {"time": "3.3s", "activity": "Sending harvested credentials and cookies via HTTP POST to exfil URL", "category": "C2 Connection", "severity": "Critical"}
            ],
            "mitre": [
                ("T1003", "OS Credential Dumping", "Adversaries may attempt to dump credentials, passwords, and hashes from system storage databases (e.g. LSASS process memory or SAM registry) to obtain administrator credentials.", "This file attempts to extract and steal your saved usernames and passwords directly from your computer's memory storage."),
                ("T1041", "Exfiltration Over C2 Channel", "Adversaries may steal sensitive user data and exfiltrate it by sending it over an established command and control (C2) network tunnel.", "This file gathers confidential information from your computer and uploads it secretly to an external server run by threat actors."),
                ("T1562", "Impair Defenses (Disable Security Tools)", "Adversaries may disable local security monitoring tools, firewalls, or Windows Defender to execute payloads without logging detections.", "This file tries to turn off Windows Defender or disable your firewalls to make it easier to run malicious activities undetected.")
            ],
            "iocs": [
                ("IP", "91.219.29.44"),
                ("Domain", "fast-downloads.ru"),
                ("URL", "https://fast-downloads.ru/upload.php")
            ]
        },
        {
            "filename": "update_agent.exe",
            "hash": "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92",
            "upload_date": "2026-06-14 09:12:00",
            "risk_score": 90,
            "risk_level": "Critical",
            "file_size": 420000,
            "malware_category": "Remote Access Trojan (RAT)",
            "description": "A remote access backdoor enabling unauthorized system configuration, command execution, and interactive control.",
            "beginner_explanation": "This file acts like a backdoor into your computer. It creates a secret passageway that allows an attacker from the internet to log into your machine, run commands, view your screen, and control your system from anywhere in the world.",
            "extension": ".exe",
            "behaviors": [
                {"time": "0.1s", "activity": "Process spawned via Windows Command Prompt", "category": "Execution", "severity": "Info"},
                {"time": "0.7s", "activity": "Creating persistent Scheduled Task 'SystemUpdater' to run at startup", "category": "Persistence", "severity": "High"},
                {"time": "1.3s", "activity": "Spawning PowerShell with encoded script execution payload", "category": "Execution", "severity": "Critical"},
                {"time": "2.2s", "activity": "Dumping local Security Accounts Manager (SAM) database registries", "category": "Credential Access", "severity": "Critical"},
                {"time": "3.0s", "activity": "Establishing permanent reverse-shell connection to 104.244.42.1 on port 4444", "category": "C2 Connection", "severity": "Critical"}
            ],
            "mitre": [
                ("T1059", "Command and Scripting Interpreter (PowerShell)", "Adversaries may abuse command and scripting interpreters (specifically PowerShell) to execute malicious commands, scripts, and payloads.", "This file uses hidden command-line scripts (PowerShell) to bypass security blocks and run commands without your knowledge."),
                ("T1547", "Boot or Logon Autostart Execution (Registry Run Keys)", "Adversaries may modify startup registry run keys or file locations to achieve automatic execution of payloads when the system boots up or users login.", "This file changes your computer's startup registry settings so it launches automatically every time you turn on your computer."),
                ("T1041", "Exfiltration Over C2 Channel", "Adversaries may steal sensitive user data and exfiltrate it by sending it over an established command and control (C2) network tunnel.", "This file gathers confidential information from your computer and uploads it secretly to an external server run by threat actors."),
                ("T1053", "Scheduled Task/Job", "Adversaries may abuse system scheduling utilities (like Windows Task Scheduler) to register periodic, repeating background executions of a payload.", "This file sets up a hidden background timer task that forces the malware to run repeatedly at scheduled times.")
            ],
            "iocs": [
                ("IP", "104.244.42.1"),
                ("Domain", "dynamic-c2.ddns.net")
            ]
        },
        {
            "filename": "coupon_installer.msi",
            "hash": "41a3b8d96aff3ca12020c923adc6c92d5a86aff3ca12020c923adc6c927f8fafc",
            "upload_date": "2026-06-15 16:35:00",
            "risk_score": 45,
            "risk_level": "Medium",
            "file_size": 1250000,
            "malware_category": "Adware / PUP",
            "description": "A potentially unwanted program (PUP) that modifies browser configurations and routes traffic through ad networks.",
            "beginner_explanation": "This file is a piece of adware. It is not designed to steal passwords or encrypt files, but it will modify your web browser settings to show you unwanted, annoying pop-up advertisements and redirect your searches to sketchy websites.",
            "extension": ".msi",
            "behaviors": [
                {"time": "0.1s", "activity": "Installer launched by user", "category": "Execution", "severity": "Info"},
                {"time": "0.9s", "activity": "Modifying browser default home page registry configuration settings", "category": "Persistence", "severity": "Medium"},
                {"time": "2.5s", "activity": "Initiating connection to telemetry tracking server: ad-clicker-network.xyz", "category": "C2 Connection", "severity": "Low"}
            ],
            "mitre": [
                ("T1547", "Boot or Logon Autostart Execution (Registry Run Keys)", "Adversaries may modify startup registry run keys or file locations to achieve automatic execution of payloads when the system boots up or users login.", "This file changes your computer's startup registry settings so it launches automatically every time you turn on your computer."),
                ("T1041", "Exfiltration Over C2 Channel", "Adversaries may steal sensitive user data and exfiltrate it by sending it over an established command and control (C2) network tunnel.", "This file gathers confidential information from your computer and uploads it secretly to an external server run by threat actors.")
            ],
            "iocs": [
                ("Domain", "ad-clicker-network.xyz"),
                ("URL", "http://ad-clicker-network.xyz/track?id=992")
            ]
        },
        {
            "filename": "fiscal_invoice.docx",
            "hash": "37f8fafc2f9547d6e6a17b07db3d8fcf533d1b329486c9d81d2e1bdf32263152",
            "upload_date": "2026-06-16 11:20:00",
            "risk_score": 5,
            "risk_level": "Low",
            "file_size": 45000,
            "malware_category": "Benign",
            "description": "A verified clean binary that utilizes standard OS APIs and shows no indicators of suspicious behavior.",
            "beginner_explanation": "Good news! This file is clean and completely safe to use. It doesn't perform any malicious actions and uses standard system routines just like any normal app or document on your computer.",
            "extension": ".docx",
            "behaviors": [
                {"time": "0.1s", "activity": "Process launched successfully", "category": "Execution", "severity": "Info"},
                {"time": "1.0s", "activity": "Reading application config file", "category": "Discovery", "severity": "Info"},
                {"time": "1.8s", "activity": "Application completed execution cycle cleanly", "category": "Execution", "severity": "Info"}
            ],
            "mitre": [],
            "iocs": []
        }
    ]
    
    for s in mock_samples:
        file_ref = db.collection("uploaded_files").document()
        file_id = file_ref.id
        
        file_ref.set({
            "filename": s["filename"],
            "hash": s["hash"],
            "upload_date": s["upload_date"],
            "file_size": s["file_size"],
            "extension": s["extension"],
            "user_id": user_id
        })
        
        # Generate simulated multi-source reports and correlate them
        plugin_results = run_all_plugins(s["filename"], s["hash"])
        corr_res = correlate_all_sources(plugin_results)
        
        # Insert Analysis Results
        db.collection("analysis_results").document(file_id).set({
            "risk_score": corr_res["final_score"],
            "risk_level": corr_res["threat_level"],
            "malware_category": s["malware_category"],
            "description": s["description"],
            "beginner_explanation": s["beginner_explanation"],
            "behaviors_json": json.dumps(s["behaviors"]),
            "vt_json": json.dumps(plugin_results.get("virustotal")),
            "anyrun_json": json.dumps(plugin_results.get("anyrun")),
            "malwarebazaar_json": json.dumps(plugin_results.get("malwarebazaar")),
            "opswat_json": json.dumps(plugin_results.get("opswat")),
            "jotti_json": json.dumps(plugin_results.get("jotti")),
            "cape_json": json.dumps(plugin_results.get("cape")),
            "abuseipdb_json": json.dumps(plugin_results.get("abuseipdb")),
            "correlation_json": json.dumps(corr_res)
        })
        
        # Seed IOCs into ioc_database
        for ioc in s["iocs"]:
            db.collection("ioc_database").add({
                "file_id": file_id,
                "user_id": user_id,
                "ioc_type": ioc[0],
                "ioc_value": ioc[1]
            })
            
        # Seed MITRE Mappings
        for m in s["mitre"]:
            db.collection("mitre_mapping").add({
                "file_id": file_id,
                "user_id": user_id,
                "technique_id": m[0],
                "technique_name": m[1],
                "technique_description": m[2],
                "beginner_explanation": m[3]
            })
            
        # Seed reports record into incident_reports
        db.collection("incident_reports").add({
            "file_id": file_id,
            "user_id": user_id,
            "report_path": f"incident_report_{file_id}_{s['filename']}.pdf",
            "created_at": s["upload_date"]
        })

# --- ROUTES ---

@app.route("/")
def index():
    if "logged_in" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        db = get_db()
        user_ref = db.collection("users").document(username).get()
        
        if user_ref.exists:
            user = user_ref.to_dict()
            if check_password_hash(user["password"], password):
                session["logged_in"] = True
                session["user_id"] = username
                session["username"] = username
                session["role"] = user.get("role", "Security Analyst")
                flash(f"Access granted. Welcome back, {username}.", "success")
                return redirect(url_for("dashboard"))
        
        flash("Invalid credentials. Access Denied.", "danger")
            
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if "logged_in" in session:
        return redirect(url_for("dashboard"))
        
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        
        if not username or not password or not confirm_password:
            flash("All fields are required.", "danger")
            return render_template("register.html")
            
        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("register.html")
            
        db = get_db()
        user_ref = db.collection("users").document(username).get()
        
        if user_ref.exists:
            flash("Username already exists.", "danger")
            return render_template("register.html")
            
        hashed_password = generate_password_hash(password)
        db.collection("users").document(username).set({
            "password": hashed_password,
            "role": "Security Analyst"
        })
        
        flash("Registration successful. You can now log in.", "success")
        return redirect(url_for("login"))
        
    return render_template("register.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Session terminated successfully.", "success")
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    if "logged_in" not in session:
        return redirect(url_for("login"))
        
    db = get_db()
    user_id = session.get("user_id")
    
    # Fetch user's files
    files_ref = db.collection("uploaded_files").where("user_id", "==", user_id).stream()
    files = []
    for doc in files_ref:
        f_data = doc.to_dict()
        f_data["id"] = doc.id
        
        # Fetch corresponding analysis results
        ar_ref = db.collection("analysis_results").document(doc.id).get()
        if ar_ref.exists:
            ar_data = ar_ref.to_dict()
            f_data["risk_score"] = ar_data.get("risk_score")
            f_data["risk_level"] = ar_data.get("risk_level")
            f_data["malware_category"] = ar_data.get("malware_category")
        else:
            f_data["risk_score"] = None
            f_data["risk_level"] = None
            f_data["malware_category"] = "Unknown"
        files.append(f_data)
        
    # Sort files by upload_date DESC
    files.sort(key=lambda x: x.get("upload_date", ""), reverse=True)
    
    # Calculate statistics filtered by user
    total_scanned = len(files)
    
    # Calculate risk counts
    low_count = sum(1 for f in files if f.get("risk_score") is not None and f["risk_score"] <= 30)
    medium_count = sum(1 for f in files if f.get("risk_score") is not None and 30 < f["risk_score"] <= 60)
    high_count = sum(1 for f in files if f.get("risk_score") is not None and 60 < f["risk_score"] <= 80)
    critical_count = sum(1 for f in files if f.get("risk_score") is not None and f["risk_score"] > 80)
    
    # Fetch user's IOCs from ioc_database
    iocs_ref = db.collection("ioc_database").where("user_id", "==", user_id).stream()
    iocs_list = [doc.to_dict() for doc in iocs_ref]
    total_iocs = len(iocs_list)
    
    # Fetch user's MITRE mappings
    mitre_ref = db.collection("mitre_mapping").where("user_id", "==", user_id).stream()
    mitre_list = [doc.to_dict() for doc in mitre_ref]
    total_mitre = len(set(m["technique_id"] for m in mitre_list))
    
    # Category counts
    category_counts = {
        "Ransomware": 0,
        "Trojan / Credential Stealer": 0,
        "Remote Access Trojan (RAT)": 0,
        "Adware / PUP": 0,
        "Benign": 0
    }
    for f in files:
        cat = f.get("malware_category")
        if cat in category_counts:
            category_counts[cat] += 1
        elif cat:
            category_counts[cat] = category_counts.get(cat, 0) + 1
            
    # IOC counts by type
    ioc_counts = {}
    for ioc in iocs_list:
        t = ioc.get("ioc_type")
        if t:
            ioc_counts[t] = ioc_counts.get(t, 0) + 1
            
    # MITRE technique counts
    mitre_counts = {}
    for m in mitre_list:
        tid = m.get("technique_id")
        if tid:
            mitre_counts[tid] = mitre_counts.get(tid, 0) + 1
            
    stats = {
        "total_scanned": total_scanned,
        "total_iocs": total_iocs,
        "total_mitre": total_mitre,
        "risk_counts": {
            "low": low_count,
            "medium": medium_count,
            "high": high_count,
            "critical": critical_count
        },
        "category_counts": category_counts,
        "ioc_counts": ioc_counts,
        "mitre_counts": mitre_counts
    }
    
    return render_template("dashboard.html", files=files, stats=stats)


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "logged_in" not in session:
        return redirect(url_for("login"))
        
    if request.method == "POST":
        if "file" not in request.files:
            flash("No file part uploaded.", "danger")
            return redirect(request.url)
            
        file = request.files["file"]
        if file.filename == "":
            flash("No selected file target.", "danger")
            return redirect(request.url)
            
        if file:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            
            # Save file locally (simulation)
            file.save(filepath)
            
            # 1. Run Static Analysis
            static_res = analyze_file(filepath, filename)
            file_hash = static_res["sha256"]
            
            # 2. Run Dynamic Analysis (Simulation)
            dynamic_res = simulate_dynamic_analysis(filename, file_hash)
            
            # 3. Calculate Risk Score
            risk_res = calculate_risk_score(static_res, dynamic_res)
            
            # 3a. Run simulated multi-source intelligence plugins and correlate them
            plugin_results = run_all_plugins(filename, file_hash)
            corr_res = correlate_all_sources(plugin_results)
            
            db = get_db()
            upload_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            file_size = static_res["file_size_bytes"]
            ext = static_res["extension"]
            
            try:
                user_id = session.get("user_id")
                
                # Insert uploaded file metadata
                file_ref = db.collection("uploaded_files").document()
                file_id = file_ref.id
                
                file_ref.set({
                    "filename": filename,
                    "hash": file_hash,
                    "upload_date": upload_date,
                    "file_size": file_size,
                    "extension": ext,
                    "user_id": user_id
                })
                
                # Insert analysis results
                db.collection("analysis_results").document(file_id).set({
                    "risk_score": corr_res["final_score"],
                    "risk_level": corr_res["threat_level"],
                    "malware_category": dynamic_res["category"],
                    "description": dynamic_res["description"],
                    "beginner_explanation": get_beginner_explanation(corr_res["final_score"]),
                    "behaviors_json": json.dumps(dynamic_res["behaviors"]),
                    "vt_json": json.dumps(plugin_results.get("virustotal")),
                    "anyrun_json": json.dumps(plugin_results.get("anyrun")),
                    "malwarebazaar_json": json.dumps(plugin_results.get("malwarebazaar")),
                    "opswat_json": json.dumps(plugin_results.get("opswat")),
                    "jotti_json": json.dumps(plugin_results.get("jotti")),
                    "cape_json": json.dumps(plugin_results.get("cape")),
                    "abuseipdb_json": json.dumps(plugin_results.get("abuseipdb")),
                    "correlation_json": json.dumps(corr_res)
                })
                
                # 4. Extract and store IOCs into ioc_database
                extract_and_store_iocs(file_id, dynamic_res["iocs"], dynamic_res["behaviors"], db)
                
                # 5. Map and store MITRE ATT&CK mappings
                map_and_store_mitre(file_id, dynamic_res["mitre_techniques"], db)
                
                # 6. Store in incident_reports table
                report_path = f"incident_report_{file_id}_{filename}.pdf"
                db.collection("incident_reports").add({
                    "file_id": file_id,
                    "user_id": user_id,
                    "report_path": report_path,
                    "created_at": upload_date
                })
                
            except Exception as e:
                flash(f"Error compiling diagnostics: {str(e)}", "danger")
                return redirect(request.url)
                
            # Clean up uploaded file from storage since we do not execute it
            try:
                if os.path.exists(filepath):
                    os.remove(filepath)
            except Exception:
                pass
                
            flash(f"Malware behavior scan completed for target '{filename}'.", "success")
            return redirect(url_for("analysis", file_id=file_id))
            
    return render_template("upload.html")


@app.route("/analysis/<string:file_id>")
def analysis(file_id):
    if "logged_in" not in session:
        return redirect(url_for("login"))
        
    db = get_db()
    user_id = session.get("user_id")
    
    file_ref = db.collection("uploaded_files").document(file_id).get()
    if not file_ref.exists:
        flash("Threat diagnostic record not found.", "danger")
        return redirect(url_for("dashboard"))
        
    file_dict = file_ref.to_dict()
    file_dict["id"] = file_ref.id
    
    if file_dict.get("user_id") != user_id:
        flash("Threat diagnostic record not found.", "danger")
        return redirect(url_for("dashboard"))
        
    ar_ref = db.collection("analysis_results").document(file_id).get()
    if ar_ref.exists:
        file_dict.update(ar_ref.to_dict())
        
    # Dynamically generate multi-source values if missing or forced
    reanalyze = request.args.get("reanalyze", "false").lower() == "true"
    if reanalyze or not file_dict.get("correlation_json") or not file_dict.get("malwarebazaar_json"):
        plugin_results = run_all_plugins(file_dict["filename"], file_dict["hash"], force_reload=reanalyze)
        corr_res = correlate_all_sources(plugin_results)
        file_dict["vt_json"] = json.dumps(plugin_results.get("virustotal"))
        file_dict["anyrun_json"] = json.dumps(plugin_results.get("anyrun"))
        file_dict["malwarebazaar_json"] = json.dumps(plugin_results.get("malwarebazaar"))
        file_dict["opswat_json"] = json.dumps(plugin_results.get("opswat"))
        file_dict["jotti_json"] = json.dumps(plugin_results.get("jotti"))
        file_dict["cape_json"] = json.dumps(plugin_results.get("cape"))
        file_dict["abuseipdb_json"] = json.dumps(plugin_results.get("abuseipdb"))
        file_dict["correlation_json"] = json.dumps(corr_res)
        
        # Write back cache to database
        db.collection("analysis_results").document(file_id).update({
            "vt_json": file_dict["vt_json"],
            "anyrun_json": file_dict["anyrun_json"],
            "malwarebazaar_json": file_dict["malwarebazaar_json"],
            "opswat_json": file_dict["opswat_json"],
            "jotti_json": file_dict["jotti_json"],
            "cape_json": file_dict["cape_json"],
            "abuseipdb_json": file_dict["abuseipdb_json"],
            "correlation_json": file_dict["correlation_json"],
            "risk_score": corr_res["final_score"],
            "risk_level": corr_res["threat_level"],
            "beginner_explanation": get_beginner_explanation(corr_res["final_score"])
        })
        file_dict["risk_score"] = corr_res["final_score"]
        file_dict["risk_level"] = corr_res["threat_level"]
        file_dict["beginner_explanation"] = get_beginner_explanation(corr_res["final_score"])
        
    # Format size
    file_size_formatted = format_size(file_dict["file_size"])
    
    # Load dynamic logs
    behaviors = json.loads(file_dict["behaviors_json"])
    
    # Load static rules indicators
    static_indicators = []
    ext = file_dict["extension"]
    if ext in ['.exe', '.js', '.vbs', '.bat', '.ps1', '.scr', '.jar', '.dll']:
        static_indicators.append(f"Suspicious executable file extension ({ext})")
    if file_dict["file_size"] < 50 * 1024 and ext in ['.exe', '.js']:
        static_indicators.append("Unusually small file size for binary payload - potential stager/downloader")
    if file_dict["risk_score"] > 80:
        static_indicators.append("Matches known threat behavior indicators in sandbox analysis")
        
    # Query IOCs from ioc_database
    iocs_ref = db.collection("ioc_database").where("file_id", "==", file_id).stream()
    iocs = [(doc.to_dict().get("ioc_type"), doc.to_dict().get("ioc_value")) for doc in iocs_ref]
    
    # Query MITRE Mappings
    mitre_ref = db.collection("mitre_mapping").where("file_id", "==", file_id).stream()
    mitre_mappings = [doc.to_dict() for doc in mitre_ref]
    
    # Generate Mitigations dynamically
    tech_ids = [m["technique_id"] for m in mitre_mappings]
    mitigations = generate_mitigations(tech_ids)
    
    return render_template(
        "analysis.html",
        file=file_dict,
        file_size_formatted=file_size_formatted,
        behaviors=behaviors,
        static_indicators=static_indicators,
        iocs=iocs,
        mitre_mappings=mitre_mappings,
        mitigations=mitigations,
        vt=json.loads(file_dict["vt_json"]) if file_dict["vt_json"] else {},
        anyrun=json.loads(file_dict["anyrun_json"]) if file_dict["anyrun_json"] else {},
        malwarebazaar=json.loads(file_dict["malwarebazaar_json"]) if file_dict["malwarebazaar_json"] else {},
        opswat=json.loads(file_dict["opswat_json"]) if file_dict["opswat_json"] else {},
        jotti=json.loads(file_dict["jotti_json"]) if file_dict["jotti_json"] else {},
        cape=json.loads(file_dict["cape_json"]) if file_dict["cape_json"] else {},
        abuseipdb=json.loads(file_dict["abuseipdb_json"]) if file_dict["abuseipdb_json"] else {},
        correlation=json.loads(file_dict["correlation_json"]) if file_dict["correlation_json"] else {}
    )

@app.route("/report_web/<string:file_id>")
def report_web(file_id):
    if "logged_in" not in session:
        return redirect(url_for("login"))
        
    db = get_db()
    user_id = session.get("user_id")
    
    file_ref = db.collection("uploaded_files").document(file_id).get()
    if not file_ref.exists:
        flash("Threat diagnostic record not found.", "danger")
        return redirect(url_for("dashboard"))
        
    file_dict = file_ref.to_dict()
    file_dict["id"] = file_ref.id
    
    if file_dict.get("user_id") != user_id:
        flash("Threat diagnostic record not found.", "danger")
        return redirect(url_for("dashboard"))
        
    ar_ref = db.collection("analysis_results").document(file_id).get()
    if ar_ref.exists:
        file_dict.update(ar_ref.to_dict())
        
    # Dynamically generate multi-source values if missing
    if not file_dict.get("correlation_json") or not file_dict.get("malwarebazaar_json"):
        plugin_results = run_all_plugins(file_dict["filename"], file_dict["hash"])
        corr_res = correlate_all_sources(plugin_results)
        file_dict["vt_json"] = json.dumps(plugin_results.get("virustotal"))
        file_dict["anyrun_json"] = json.dumps(plugin_results.get("anyrun"))
        file_dict["malwarebazaar_json"] = json.dumps(plugin_results.get("malwarebazaar"))
        file_dict["opswat_json"] = json.dumps(plugin_results.get("opswat"))
        file_dict["jotti_json"] = json.dumps(plugin_results.get("jotti"))
        file_dict["cape_json"] = json.dumps(plugin_results.get("cape"))
        file_dict["abuseipdb_json"] = json.dumps(plugin_results.get("abuseipdb"))
        file_dict["correlation_json"] = json.dumps(corr_res)
        
        # Write back cache to database
        db.collection("analysis_results").document(file_id).update({
            "vt_json": file_dict["vt_json"],
            "anyrun_json": file_dict["anyrun_json"],
            "malwarebazaar_json": file_dict["malwarebazaar_json"],
            "opswat_json": file_dict["opswat_json"],
            "jotti_json": file_dict["jotti_json"],
            "cape_json": file_dict["cape_json"],
            "abuseipdb_json": file_dict["abuseipdb_json"],
            "correlation_json": file_dict["correlation_json"],
            "risk_score": corr_res["final_score"],
            "risk_level": corr_res["threat_level"],
            "beginner_explanation": get_beginner_explanation(corr_res["final_score"])
        })
        file_dict["risk_score"] = corr_res["final_score"]
        file_dict["risk_level"] = corr_res["threat_level"]
        file_dict["beginner_explanation"] = get_beginner_explanation(corr_res["final_score"])
        
    file_size_formatted = format_size(file_dict["file_size"])
    behaviors = json.loads(file_dict["behaviors_json"])
    
    # Generate static indicators
    static_indicators = []
    ext = file_dict["extension"]
    if ext in ['.exe', '.js', '.vbs', '.bat', '.ps1', '.scr', '.jar', '.dll']:
        static_indicators.append(f"Suspicious executable file extension ({ext})")
    if file_dict["file_size"] < 50 * 1024 and ext in ['.exe', '.js']:
        static_indicators.append("Unusually small file size for binary payload")
    if file_dict["risk_score"] > 80:
        static_indicators.append("Matches known threat signature databases")
        
    # Query IOCs from ioc_database
    iocs_ref = db.collection("ioc_database").where("file_id", "==", file_id).stream()
    iocs = [(doc.to_dict().get("ioc_type"), doc.to_dict().get("ioc_value")) for doc in iocs_ref]
    
    # Query MITRE Mappings
    mitre_ref = db.collection("mitre_mapping").where("file_id", "==", file_id).stream()
    mitre_mappings = [doc.to_dict() for doc in mitre_ref]
    
    # Generate Mitigations dynamically
    tech_ids = [m["technique_id"] for m in mitre_mappings]
    mitigations = generate_mitigations(tech_ids)
    
    return render_template(
        "report.html",
        file=file_dict,
        file_size_formatted=file_size_formatted,
        behaviors=behaviors,
        static_indicators=static_indicators,
        iocs=iocs,
        mitre_mappings=mitre_mappings,
        mitigations=mitigations,
        vt=json.loads(file_dict["vt_json"]) if file_dict["vt_json"] else {},
        anyrun=json.loads(file_dict["anyrun_json"]) if file_dict["anyrun_json"] else {},
        malwarebazaar=json.loads(file_dict["malwarebazaar_json"]) if file_dict["malwarebazaar_json"] else {},
        opswat=json.loads(file_dict["opswat_json"]) if file_dict["opswat_json"] else {},
        jotti=json.loads(file_dict["jotti_json"]) if file_dict["jotti_json"] else {},
        cape=json.loads(file_dict["cape_json"]) if file_dict["cape_json"] else {},
        abuseipdb=json.loads(file_dict["abuseipdb_json"]) if file_dict["abuseipdb_json"] else {},
        correlation=json.loads(file_dict["correlation_json"]) if file_dict["correlation_json"] else {}
    )

@app.route("/report_pdf/<string:file_id>")
def report_pdf(file_id):
    if "logged_in" not in session:
        return redirect(url_for("login"))
        
    db = get_db()
    user_id = session.get("user_id")
    
    # Fetch file details and analysis results
    file_ref = db.collection("uploaded_files").document(file_id).get()
    if not file_ref.exists:
        flash("Threat record not found.", "danger")
        return redirect(url_for("dashboard"))
        
    file_dict = file_ref.to_dict()
    file_dict["id"] = file_ref.id
    
    if file_dict.get("user_id") != user_id:
        flash("Threat record not found.", "danger")
        return redirect(url_for("dashboard"))
        
    ar_ref = db.collection("analysis_results").document(file_id).get()
    if ar_ref.exists:
        file_dict.update(ar_ref.to_dict())
        
    # Dynamically generate multi-source values if missing
    if not file_dict.get("correlation_json") or not file_dict.get("malwarebazaar_json"):
        plugin_results = run_all_plugins(file_dict["filename"], file_dict["hash"])
        corr_res = correlate_all_sources(plugin_results)
        file_dict["vt_json"] = json.dumps(plugin_results.get("virustotal"))
        file_dict["anyrun_json"] = json.dumps(plugin_results.get("anyrun"))
        file_dict["malwarebazaar_json"] = json.dumps(plugin_results.get("malwarebazaar"))
        file_dict["opswat_json"] = json.dumps(plugin_results.get("opswat"))
        file_dict["jotti_json"] = json.dumps(plugin_results.get("jotti"))
        file_dict["cape_json"] = json.dumps(plugin_results.get("cape"))
        file_dict["abuseipdb_json"] = json.dumps(plugin_results.get("abuseipdb"))
        file_dict["correlation_json"] = json.dumps(corr_res)
        
        # Write back cache to database
        db.collection("analysis_results").document(file_id).update({
            "vt_json": file_dict["vt_json"],
            "anyrun_json": file_dict["anyrun_json"],
            "malwarebazaar_json": file_dict["malwarebazaar_json"],
            "opswat_json": file_dict["opswat_json"],
            "jotti_json": file_dict["jotti_json"],
            "cape_json": file_dict["cape_json"],
            "abuseipdb_json": file_dict["abuseipdb_json"],
            "correlation_json": file_dict["correlation_json"],
            "risk_score": corr_res["final_score"],
            "risk_level": corr_res["threat_level"],
            "beginner_explanation": get_beginner_explanation(corr_res["final_score"])
        })
        file_dict["risk_score"] = corr_res["final_score"]
        file_dict["risk_level"] = corr_res["threat_level"]
        file_dict["beginner_explanation"] = get_beginner_explanation(corr_res["final_score"])
        
    # Generate static indicators
    static_indicators = []
    ext = file_dict["extension"]
    if ext in ['.exe', '.js', '.vbs', '.bat', '.ps1', '.scr', '.jar', '.dll']:
        static_indicators.append(f"Suspicious executable file extension ({ext})")
    if file_dict["file_size"] < 50 * 1024 and ext in ['.exe', '.js']:
        static_indicators.append("Unusually small file size - potential stager")
    if file_dict["risk_score"] > 80:
        static_indicators.append("Matches known threat signatures")
    file_dict["static_indicators"] = static_indicators
    file_dict["behaviors"] = json.loads(file_dict["behaviors_json"])
    
    # Fetch vt, anyrun and correlation dicts
    file_dict["vt"] = json.loads(file_dict["vt_json"]) if file_dict["vt_json"] else {}
    file_dict["anyrun"] = json.loads(file_dict["anyrun_json"]) if file_dict["anyrun_json"] else {}
    file_dict["malwarebazaar"] = json.loads(file_dict["malwarebazaar_json"]) if file_dict["malwarebazaar_json"] else {}
    file_dict["opswat"] = json.loads(file_dict["opswat_json"]) if file_dict["opswat_json"] else {}
    file_dict["jotti"] = json.loads(file_dict["jotti_json"]) if file_dict["jotti_json"] else {}
    file_dict["cape"] = json.loads(file_dict["cape_json"]) if file_dict["cape_json"] else {}
    file_dict["abuseipdb"] = json.loads(file_dict["abuseipdb_json"]) if file_dict["abuseipdb_json"] else {}
    file_dict["correlation"] = json.loads(file_dict["correlation_json"]) if file_dict["correlation_json"] else {}
    
    # Fetch IOCs from ioc_database
    iocs_ref = db.collection("ioc_database").where("file_id", "==", file_id).stream()
    iocs = [(doc.to_dict()["ioc_type"], doc.to_dict()["ioc_value"]) for doc in iocs_ref]
    
    # Fetch MITRE mappings
    mitre_ref = db.collection("mitre_mapping").where("file_id", "==", file_id).stream()
    mitre_mappings = [doc.to_dict() for doc in mitre_ref]
    
    # Fetch mitigations
    tech_ids = [m["technique_id"] for m in mitre_mappings]
    mitigations = generate_mitigations(tech_ids)
    
    # Generate PDF report using report_generator module
    try:
        report_pdf_name = generate_pdf_report(file_dict, iocs, mitre_mappings, mitigations, app.config["REPORTS_FOLDER"])
        return send_from_directory(app.config["REPORTS_FOLDER"], report_pdf_name, as_attachment=True)
    except Exception as e:
        flash(f"Error generating PDF incident report: {str(e)}", "danger")
        return redirect(url_for("analysis", file_id=file_id))

@app.route("/delete_file/<string:file_id>", methods=["POST"])
def delete_file(file_id):
    if "logged_in" not in session:
        flash("Unauthorized command. Login required to purge threat logs.", "danger")
        return redirect(url_for("dashboard"))
        
    db = get_db()
    user_id = session.get("user_id")
    
    # Get PDF file path to delete it from disk
    reports_ref = db.collection("incident_reports").where("file_id", "==", file_id).where("user_id", "==", user_id).stream()
    reports = [doc.to_dict() for doc in reports_ref]
    
    try:
        # Delete from uploaded_files, analysis_results, ioc_database, mitre_mapping, incident_reports
        db.collection("uploaded_files").document(file_id).delete()
        db.collection("analysis_results").document(file_id).delete()
        
        iocs_ref = db.collection("ioc_database").where("file_id", "==", file_id).stream()
        for doc in iocs_ref:
            doc.reference.delete()
            
        mitre_ref = db.collection("mitre_mapping").where("file_id", "==", file_id).stream()
        for doc in mitre_ref:
            doc.reference.delete()
            
        reports_del_ref = db.collection("incident_reports").where("file_id", "==", file_id).stream()
        for doc in reports_del_ref:
            doc.reference.delete()
            
        # Manually delete PDF file from reports directory if it exists
        if reports:
            pdf_path = os.path.join(app.config["REPORTS_FOLDER"], reports[0]["report_path"])
            if os.path.exists(pdf_path):
                os.remove(pdf_path)
                
        flash("Threat incident logs purged successfully.", "success")
    except Exception as e:
        flash(f"Error purging threat record: {str(e)}", "danger")
        
    return redirect(url_for("dashboard"))

def format_size(size_bytes):
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.2f} MB"

# Initialize DB on startup
init_db()

if __name__ == "__main__":
    app.run(debug=True)
