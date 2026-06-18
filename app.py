import os
import json
import sqlite3
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory

# Import modular analysis engines
from modules.static_analysis import analyze_file
from modules.dynamic_analysis import simulate_dynamic_analysis
from modules.ioc_extractor import extract_and_store_iocs
from modules.mitre_mapper import map_and_store_mitre
from modules.risk_engine import calculate_risk_score
from modules.mitigation_engine import generate_mitigations
from modules.report_generator import generate_pdf_report
from modules.plugin_manager import run_all_plugins
from modules.unified_correlation_engine import correlate_all_sources

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "cybersecurity_simulation_secret_key"

# Paths
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_DIR = os.path.join(BASE_DIR, "database")
DB_PATH = os.path.join(DB_DIR, "malware_platform.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
REPORTS_FOLDER = os.path.join(BASE_DIR, "static", "reports")

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["REPORTS_FOLDER"] = REPORTS_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024 # 16 MB limit (standard)

# Ensure workspace folders exist
os.makedirs(DB_DIR, exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORTS_FOLDER, exist_ok=True)

def get_db():
    """Returns a connection to the SQLite database."""
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database schema and seeds initial data."""
    conn = get_db()
    cursor = conn.cursor()
    
    # Create Tables matching the requested schema exactly
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT
    );
    """)
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS uploaded_files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT,
        hash TEXT,
        upload_date TEXT,
        file_size INTEGER,
        extension TEXT
    );
    """)
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ioc_database (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_id INTEGER,
        ioc_type TEXT,
        ioc_value TEXT,
        FOREIGN KEY(file_id) REFERENCES uploaded_files(id) ON DELETE CASCADE
    );
    """)
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS mitre_mapping (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_id INTEGER,
        technique_id TEXT,
        technique_name TEXT,
        technique_description TEXT,
        beginner_explanation TEXT,
        FOREIGN KEY(file_id) REFERENCES uploaded_files(id) ON DELETE CASCADE
    );
    """)
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS analysis_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_id INTEGER,
        risk_score INTEGER,
        risk_level TEXT,
        malware_category TEXT,
        description TEXT,
        beginner_explanation TEXT,
        behaviors_json TEXT,
        vt_json TEXT,
        anyrun_json TEXT,
        malwarebazaar_json TEXT,
        opswat_json TEXT,
        jotti_json TEXT,
        cape_json TEXT,
        abuseipdb_json TEXT,
        correlation_json TEXT,
        FOREIGN KEY(file_id) REFERENCES uploaded_files(id) ON DELETE CASCADE
    );
    """)
    
    # Dynamic schema migrations for multi-source correlation engine columns
    cursor.execute("PRAGMA table_info(analysis_results);")
    columns = [row[1] for row in cursor.fetchall()]
    for col in ["vt_json", "anyrun_json", "malwarebazaar_json", "opswat_json", "jotti_json", "cape_json", "abuseipdb_json", "correlation_json"]:
        if col not in columns:
            cursor.execute(f"ALTER TABLE analysis_results ADD COLUMN {col} TEXT;")
            
    # Dynamic schema migration for user_id on uploaded_files
    cursor.execute("PRAGMA table_info(uploaded_files);")
    uploaded_cols = [row[1] for row in cursor.fetchall()]
    if "user_id" not in uploaded_cols:
        cursor.execute("ALTER TABLE uploaded_files ADD COLUMN user_id INTEGER;")
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incident_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_id INTEGER,
        report_path TEXT,
        created_at TEXT,
        FOREIGN KEY(file_id) REFERENCES uploaded_files(id) ON DELETE CASCADE
    );
    """)
    
    # Seed kamalesh Analyst credential
    cursor.execute("DELETE FROM users WHERE username NOT IN ('kamalesh', 'admin')")
    
    # Ensure kamalesh exists
    cursor.execute("SELECT * FROM users WHERE username = 'kamalesh'")
    kamalesh_user = cursor.fetchone()
    kamalesh_pass = generate_password_hash("Kamalesh@2006")
    if not kamalesh_user:
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ("kamalesh", kamalesh_pass, "Security Analyst"))
    else:
        cursor.execute("UPDATE users SET password = ?, role = ? WHERE username = 'kamalesh'", (kamalesh_pass, "Security Analyst"))
        
    # Ensure admin exists
    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    admin_user = cursor.fetchone()
    admin_pass = generate_password_hash("admin123")
    if not admin_user:
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ("admin", admin_pass, "Admin"))
        
    conn.commit()
        
    # Seed Mock Analysis Records if table is empty
    cursor.execute("SELECT COUNT(*) FROM uploaded_files")
    if cursor.fetchone()[0] == 0:
        cursor.execute("SELECT id FROM users WHERE username = 'kamalesh'")
        kam_row = cursor.fetchone()
        kam_id = kam_row["id"] if kam_row else None
        seed_mock_data(conn, kam_id)
        
    conn.close()

def seed_mock_data(conn, user_id):
    """Pre-populates database with sample scans to verify charts on first load."""
    cursor = conn.cursor()
    
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
        cursor.execute(
            """
            INSERT INTO uploaded_files 
            (filename, hash, upload_date, file_size, extension, user_id)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                s["filename"], 
                s["hash"], 
                s["upload_date"], 
                s["file_size"], 
                s["extension"],
                user_id
            )
        )
        file_id = cursor.lastrowid
        
        # Generate simulated multi-source reports and correlate them
        plugin_results = run_all_plugins(s["filename"], s["hash"])
        corr_res = correlate_all_sources(plugin_results)
        
        # Insert Analysis Results with correlated outcomes
        cursor.execute(
            """
            INSERT INTO analysis_results
            (file_id, risk_score, risk_level, malware_category, description, beginner_explanation, behaviors_json, 
             vt_json, anyrun_json, malwarebazaar_json, opswat_json, jotti_json, cape_json, abuseipdb_json, correlation_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                file_id,
                corr_res["final_score"],
                corr_res["threat_level"],
                s["malware_category"],
                s["description"],
                s["beginner_explanation"],
                json.dumps(s["behaviors"]),
                json.dumps(plugin_results.get("virustotal")),
                json.dumps(plugin_results.get("anyrun")),
                json.dumps(plugin_results.get("malwarebazaar")),
                json.dumps(plugin_results.get("opswat")),
                json.dumps(plugin_results.get("jotti")),
                json.dumps(plugin_results.get("cape")),
                json.dumps(plugin_results.get("abuseipdb")),
                json.dumps(corr_res)
            )
        )
        
        # Seed IOCs into ioc_database
        for ioc in s["iocs"]:
            cursor.execute(
                "INSERT INTO ioc_database (file_id, ioc_type, ioc_value) VALUES (?, ?, ?)",
                (file_id, ioc[0], ioc[1])
            )
            
        # Seed MITRE Mappings
        for m in s["mitre"]:
            cursor.execute(
                """
                INSERT INTO mitre_mapping 
                (file_id, technique_id, technique_name, technique_description, beginner_explanation) 
                VALUES (?, ?, ?, ?, ?)
                """,
                (file_id, m[0], m[1], m[2], m[3])
            )
            
        # Seed reports record into incident_reports
        cursor.execute(
            "INSERT INTO incident_reports (file_id, report_path, created_at) VALUES (?, ?, ?)",
            (file_id, f"incident_report_{file_id}_{s['filename']}.pdf", s["upload_date"])
        )
        
    conn.commit()

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
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user["password"], password):
            session["logged_in"] = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            flash(f"Access granted. Welcome back, {username}.", "success")
            return redirect(url_for("dashboard"))
        else:
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
            
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            conn.close()
            flash("Username already exists.", "danger")
            return render_template("register.html")
            
        hashed_password = generate_password_hash(password)
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, hashed_password, "Security Analyst"))
        conn.commit()
        conn.close()
        
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
        
    conn = get_db()
    cursor = conn.cursor()
    
    user_id = session.get("user_id")
    
    # Fetch user's files with joined analysis scores
    cursor.execute("""
        SELECT uf.id, uf.filename, uf.hash, uf.upload_date, ar.risk_score, ar.risk_level
        FROM uploaded_files uf
        LEFT JOIN analysis_results ar ON uf.id = ar.file_id
        WHERE uf.user_id = ?
        ORDER BY uf.id DESC
    """, (user_id,))
    files = cursor.fetchall()
    
    # Calculate statistics filtered by user
    cursor.execute("SELECT COUNT(*) FROM uploaded_files WHERE user_id = ?", (user_id,))
    total_scanned = cursor.fetchone()[0]
    
    # Risk Counts from analysis_results filtered by user
    cursor.execute("SELECT COUNT(*) FROM analysis_results ar JOIN uploaded_files uf ON ar.file_id = uf.id WHERE uf.user_id = ? AND ar.risk_score <= 30", (user_id,))
    low_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM analysis_results ar JOIN uploaded_files uf ON ar.file_id = uf.id WHERE uf.user_id = ? AND ar.risk_score > 30 AND ar.risk_score <= 60", (user_id,))
    medium_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM analysis_results ar JOIN uploaded_files uf ON ar.file_id = uf.id WHERE uf.user_id = ? AND ar.risk_score > 60 AND ar.risk_score <= 80", (user_id,))
    high_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM analysis_results ar JOIN uploaded_files uf ON ar.file_id = uf.id WHERE uf.user_id = ? AND ar.risk_score > 80", (user_id,))
    critical_count = cursor.fetchone()[0]
    
    # Total IOCs from ioc_database filtered by user
    cursor.execute("SELECT COUNT(*) FROM ioc_database ioc JOIN uploaded_files uf ON ioc.file_id = uf.id WHERE uf.user_id = ?", (user_id,))
    total_iocs = cursor.fetchone()[0]
    
    # Total unique MITRE mapped techniques filtered by user
    cursor.execute("SELECT COUNT(DISTINCT mit.technique_id) FROM mitre_mapping mit JOIN uploaded_files uf ON mit.file_id = uf.id WHERE uf.user_id = ?", (user_id,))
    total_mitre = cursor.fetchone()[0]
    
    # Category counts from analysis_results filtered by user
    cursor.execute("SELECT ar.malware_category, COUNT(*) FROM analysis_results ar JOIN uploaded_files uf ON ar.file_id = uf.id WHERE uf.user_id = ? GROUP BY ar.malware_category", (user_id,))
    category_counts = {row[0]: row[1] for row in cursor.fetchall()}
    # Fill standard categories if not present
    for cat in ["Ransomware", "Trojan / Credential Stealer", "Remote Access Trojan (RAT)", "Adware / PUP", "Benign"]:
        if cat not in category_counts:
            category_counts[cat] = 0
            
    # IOC counts by type from ioc_database filtered by user
    cursor.execute("SELECT ioc.ioc_type, COUNT(*) FROM ioc_database ioc JOIN uploaded_files uf ON ioc.file_id = uf.id WHERE uf.user_id = ? GROUP BY ioc.ioc_type", (user_id,))
    ioc_counts = {row[0]: row[1] for row in cursor.fetchall()}
    
    # MITRE technique usage counts filtered by user
    cursor.execute("SELECT mit.technique_id, COUNT(*) FROM mitre_mapping mit JOIN uploaded_files uf ON mit.file_id = uf.id WHERE uf.user_id = ? GROUP BY mit.technique_id", (user_id,))
    mitre_counts = {row[0]: row[1] for row in cursor.fetchall()}
    
    conn.close()
    
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
            
            # Save data inside tables
            conn = get_db()
            cursor = conn.cursor()
            
            upload_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            file_size = static_res["file_size_bytes"]
            ext = static_res["extension"]
            
            try:
                user_id = session.get("user_id")
                # Insert uploaded file metadata
                cursor.execute(
                    """
                    INSERT INTO uploaded_files 
                    (filename, hash, upload_date, file_size, extension, user_id)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (filename, file_hash, upload_date, file_size, ext, user_id)
                )
                file_id = cursor.lastrowid
                
                # Insert analysis results
                cursor.execute(
                    """
                    INSERT INTO analysis_results
                    (file_id, risk_score, risk_level, malware_category, description, beginner_explanation, behaviors_json, 
                     vt_json, anyrun_json, malwarebazaar_json, opswat_json, jotti_json, cape_json, abuseipdb_json, correlation_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        file_id,
                        corr_res["final_score"],
                        corr_res["threat_level"],
                        dynamic_res["category"],
                        dynamic_res["description"],
                        risk_res["explanation"],
                        json.dumps(dynamic_res["behaviors"]),
                        json.dumps(plugin_results.get("virustotal")),
                        json.dumps(plugin_results.get("anyrun")),
                        json.dumps(plugin_results.get("malwarebazaar")),
                        json.dumps(plugin_results.get("opswat")),
                        json.dumps(plugin_results.get("jotti")),
                        json.dumps(plugin_results.get("cape")),
                        json.dumps(plugin_results.get("abuseipdb")),
                        json.dumps(corr_res)
                    )
                )
                
                # 4. Extract and store IOCs into ioc_database
                extract_and_store_iocs(file_id, dynamic_res["iocs"], dynamic_res["behaviors"], conn)
                
                # 5. Map and store MITRE ATT&CK mappings
                map_and_store_mitre(file_id, dynamic_res["mitre_techniques"], conn)
                
                # 6. Store in incident_reports table
                report_path = f"incident_report_{file_id}_{filename}.pdf"
                cursor.execute(
                    "INSERT INTO incident_reports (file_id, report_path, created_at) VALUES (?, ?, ?)",
                    (file_id, report_path, upload_date)
                )
                
                conn.commit()
                
            except Exception as e:
                conn.rollback()
                flash(f"Error compiling diagnostics: {str(e)}", "danger")
                return redirect(request.url)
            finally:
                conn.close()
                
            # Clean up uploaded file from storage since we do not execute it
            try:
                if os.path.exists(filepath):
                    os.remove(filepath)
            except Exception:
                pass
                
            flash(f"Malware behavior scan completed for target '{filename}'.", "success")
            return redirect(url_for("analysis", file_id=file_id))
            
    return render_template("upload.html")

@app.route("/analysis/<int:file_id>")
def analysis(file_id):
    if "logged_in" not in session:
        return redirect(url_for("login"))
        
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT uf.id, uf.filename, uf.hash, uf.upload_date, uf.file_size, uf.extension,
               ar.risk_score, ar.risk_level, ar.malware_category, ar.description, ar.beginner_explanation, ar.behaviors_json,
               ar.vt_json, ar.anyrun_json, ar.malwarebazaar_json, ar.opswat_json, ar.jotti_json, ar.cape_json, ar.abuseipdb_json, ar.correlation_json
        FROM uploaded_files uf
        JOIN analysis_results ar ON uf.id = ar.file_id
        WHERE uf.id = ? AND uf.user_id = ?
    """, (file_id, session.get("user_id")))
    file_record = cursor.fetchone()
    
    if not file_record:
        conn.close()
        flash("Threat diagnostic record not found.", "danger")
        return redirect(url_for("dashboard"))
        
    file_dict = dict(file_record)
    
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
        conn_write = get_db()
        cursor_write = conn_write.cursor()
        cursor_write.execute("""
            UPDATE analysis_results
            SET vt_json = ?, anyrun_json = ?, malwarebazaar_json = ?, opswat_json = ?, jotti_json = ?, cape_json = ?, abuseipdb_json = ?, correlation_json = ?, risk_score = ?, risk_level = ?
            WHERE file_id = ?
        """, (
            file_dict["vt_json"],
            file_dict["anyrun_json"],
            file_dict["malwarebazaar_json"],
            file_dict["opswat_json"],
            file_dict["jotti_json"],
            file_dict["cape_json"],
            file_dict["abuseipdb_json"],
            file_dict["correlation_json"],
            corr_res["final_score"],
            corr_res["threat_level"],
            file_id
        ))
        conn_write.commit()
        conn_write.close()
        file_dict["risk_score"] = corr_res["final_score"]
        file_dict["risk_level"] = corr_res["threat_level"]
        
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
    cursor.execute("SELECT ioc_type, ioc_value FROM ioc_database WHERE file_id = ?", (file_id,))
    iocs = cursor.fetchall()
    
    # Query MITRE Mappings
    cursor.execute("SELECT technique_id, technique_name, technique_description, beginner_explanation FROM mitre_mapping WHERE file_id = ?", (file_id,))
    mitre_mappings = cursor.fetchall()
    
    # Generate Mitigations dynamically
    tech_ids = [m["technique_id"] for m in mitre_mappings]
    mitigations = generate_mitigations(tech_ids)
    
    conn.close()
    
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

@app.route("/report_web/<int:file_id>")
def report_web(file_id):
    if "logged_in" not in session:
        return redirect(url_for("login"))
        
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT uf.id, uf.filename, uf.hash, uf.upload_date, uf.file_size, uf.extension,
               ar.risk_score, ar.risk_level, ar.malware_category, ar.description, ar.beginner_explanation, ar.behaviors_json,
               ar.vt_json, ar.anyrun_json, ar.malwarebazaar_json, ar.opswat_json, ar.jotti_json, ar.cape_json, ar.abuseipdb_json, ar.correlation_json
        FROM uploaded_files uf
        JOIN analysis_results ar ON uf.id = ar.file_id
        WHERE uf.id = ? AND uf.user_id = ?
    """, (file_id, session.get("user_id")))
    file_record = cursor.fetchone()
    
    if not file_record:
        conn.close()
        flash("Threat diagnostic record not found.", "danger")
        return redirect(url_for("dashboard"))
        
    file_dict = dict(file_record)
    
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
        conn_write = get_db()
        cursor_write = conn_write.cursor()
        cursor_write.execute("""
            UPDATE analysis_results
            SET vt_json = ?, anyrun_json = ?, malwarebazaar_json = ?, opswat_json = ?, jotti_json = ?, cape_json = ?, abuseipdb_json = ?, correlation_json = ?, risk_score = ?, risk_level = ?
            WHERE file_id = ?
        """, (
            file_dict["vt_json"],
            file_dict["anyrun_json"],
            file_dict["malwarebazaar_json"],
            file_dict["opswat_json"],
            file_dict["jotti_json"],
            file_dict["cape_json"],
            file_dict["abuseipdb_json"],
            file_dict["correlation_json"],
            corr_res["final_score"],
            corr_res["threat_level"],
            file_id
        ))
        conn_write.commit()
        conn_write.close()
        file_dict["risk_score"] = corr_res["final_score"]
        file_dict["risk_level"] = corr_res["threat_level"]
        
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
        
    cursor.execute("SELECT ioc_type, ioc_value FROM ioc_database WHERE file_id = ?", (file_id,))
    iocs = cursor.fetchall()
    
    cursor.execute("SELECT technique_id, technique_name, technique_description, beginner_explanation FROM mitre_mapping WHERE file_id = ?", (file_id,))
    mitre_mappings = cursor.fetchall()
    
    tech_ids = [m["technique_id"] for m in mitre_mappings]
    mitigations = generate_mitigations(tech_ids)
    
    conn.close()
    
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

@app.route("/report_pdf/<int:file_id>")
def report_pdf(file_id):
    if "logged_in" not in session:
        return redirect(url_for("login"))
        
    conn = get_db()
    cursor = conn.cursor()
    
    # Fetch file details and analysis results
    cursor.execute("""
        SELECT uf.id, uf.filename, uf.hash, uf.upload_date, uf.file_size, uf.extension,
               ar.risk_score, ar.risk_level, ar.malware_category, ar.description, ar.beginner_explanation, ar.behaviors_json,
               ar.vt_json, ar.anyrun_json, ar.malwarebazaar_json, ar.opswat_json, ar.jotti_json, ar.cape_json, ar.abuseipdb_json, ar.correlation_json
        FROM uploaded_files uf
        JOIN analysis_results ar ON uf.id = ar.file_id
        WHERE uf.id = ? AND uf.user_id = ?
    """, (file_id, session.get("user_id")))
    file_record = cursor.fetchone()
    
    if not file_record:
        conn.close()
        flash("Threat record not found.", "danger")
        return redirect(url_for("dashboard"))
        
    file_dict = dict(file_record)
    
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
        conn_write = get_db()
        cursor_write = conn_write.cursor()
        cursor_write.execute("""
            UPDATE analysis_results
            SET vt_json = ?, anyrun_json = ?, malwarebazaar_json = ?, opswat_json = ?, jotti_json = ?, cape_json = ?, abuseipdb_json = ?, correlation_json = ?, risk_score = ?, risk_level = ?
            WHERE file_id = ?
        """, (
            file_dict["vt_json"],
            file_dict["anyrun_json"],
            file_dict["malwarebazaar_json"],
            file_dict["opswat_json"],
            file_dict["jotti_json"],
            file_dict["cape_json"],
            file_dict["abuseipdb_json"],
            file_dict["correlation_json"],
            corr_res["final_score"],
            corr_res["threat_level"],
            file_id
        ))
        conn_write.commit()
        conn_write.close()
        file_dict["risk_score"] = corr_res["final_score"]
        file_dict["risk_level"] = corr_res["threat_level"]
        
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
    cursor.execute("SELECT ioc_type, ioc_value FROM ioc_database WHERE file_id = ?", (file_id,))
    iocs = [(row["ioc_type"], row["ioc_value"]) for row in cursor.fetchall()]
    
    # Fetch MITRE mappings
    cursor.execute("SELECT technique_id, technique_name, technique_description, beginner_explanation FROM mitre_mapping WHERE file_id = ?", (file_id,))
    mitre_mappings = [dict(row) for row in cursor.fetchall()]
    
    # Fetch mitigations
    tech_ids = [m["technique_id"] for m in mitre_mappings]
    mitigations = generate_mitigations(tech_ids)
    
    conn.close()
    
    # Generate PDF report using report_generator module
    try:
        report_pdf_name = generate_pdf_report(file_dict, iocs, mitre_mappings, mitigations, app.config["REPORTS_FOLDER"])
        return send_from_directory(app.config["REPORTS_FOLDER"], report_pdf_name, as_attachment=True)
    except Exception as e:
        flash(f"Error generating PDF incident report: {str(e)}", "danger")
        return redirect(url_for("analysis", file_id=file_id))

@app.route("/delete_file/<int:file_id>", methods=["POST"])
def delete_file(file_id):
    if "logged_in" not in session:
        flash("Unauthorized command. Login required to purge threat logs.", "danger")
        return redirect(url_for("dashboard"))
        
    conn = get_db()
    cursor = conn.cursor()
    
    user_id = session.get("user_id")
    # Get PDF file path to delete it from disk (joining with uploaded_files to verify user_id)
    cursor.execute("""
        SELECT ir.* FROM incident_reports ir
        JOIN uploaded_files uf ON ir.file_id = uf.id
        WHERE ir.file_id = ? AND uf.user_id = ?
    """, (file_id, user_id))
    report_record = cursor.fetchone()
    
    try:
        # Delete from uploaded_files (will cascade delete ioc_database, mitre_mapping, analysis_results, incident_reports)
        cursor.execute("DELETE FROM uploaded_files WHERE id = ? AND user_id = ?", (file_id, user_id))
        conn.commit()
        
        # Manually delete PDF file from reports directory if it exists
        if report_record:
            pdf_path = os.path.join(app.config["REPORTS_FOLDER"], report_record["report_path"])
            if os.path.exists(pdf_path):
                os.remove(pdf_path)
                
        flash("Threat incident logs purged successfully.", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Error purging threat record: {str(e)}", "danger")
    finally:
        conn.close()
        
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
