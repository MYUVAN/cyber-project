import os

def simulate_dynamic_analysis(filename, sha256_hash):
    """
    Simulates dynamic execution of a file in a sandbox.
    Returns deterministic mock behaviors based on file signature, extension, and filename.
    """
    profile_type = get_profile_by_filename(filename, sha256_hash)

    # Profile definitions
    profiles = {
        "Ransomware": {
            "category": "Ransomware",
            "threat_level": "Critical",
            "base_score": 95,
            "description": "A destructive ransomware threat that encrypts user data, disables recovery tools, and demands payment.",
            "beginner_explanation": "This file is extremely dangerous. It acts like a digital kidnapper, locking all your photos, documents, and files by encrypting them so you can't open them. It then tries to force you to pay money (a ransom) to get them back.",
            "behaviors": [
                {"time": "0.1s", "activity": "Process spawned from user temp directory", "category": "Execution", "severity": "Info"},
                {"time": "0.8s", "activity": "Spawning PowerShell to delete system backup shadow copies (vssadmin.exe delete shadows /all /quiet)", "category": "Defense Evasion", "severity": "Critical"},
                {"time": "1.5s", "activity": "Modifying registry run keys for boot persistence (HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run)", "category": "Persistence", "severity": "High"},
                {"time": "2.1s", "activity": "Resolving onion-gateway.net via DNS query", "category": "C2 Connection", "severity": "Medium"},
                {"time": "2.8s", "activity": "Establishing encrypted SSL network callback to C2 server: 185.220.101.5", "category": "C2 Connection", "severity": "High"},
                {"time": "3.5s", "activity": "Scanning files in C:\\Users\\Public\\Documents and C:\\Users\\Analyst\\Documents", "category": "Discovery", "severity": "Info"},
                {"time": "4.2s", "activity": "Rapid encryption of document files and appending '.crypt' extension", "category": "Impact", "severity": "Critical"},
                {"time": "5.0s", "activity": "Writing ransom note instructions (README_DECRYPT.txt) to desktop", "category": "Impact", "severity": "High"}
            ],
            "mitre_techniques": ["T1059", "T1547", "T1041", "T1486"],
            "iocs": [
                {"type": "IP", "value": "185.220.101.5"},
                {"type": "Domain", "value": "onion-gateway.net"},
                {"type": "URL", "value": "http://onion-gateway.net/handshake"},
                {"type": "File Hash", "value": "5e883f89a24a1195973410bc31460d2d31408b067f18a514d2e7ff2b32269a2d"}
            ]
        },
        "Spyware": {
            "category": "Trojan / Credential Stealer",
            "threat_level": "High",
            "base_score": 78,
            "description": "A stealthy information-stealing Trojan targeting sensitive user credentials and local browser data.",
            "beginner_explanation": "This file is a spyware program designed to spy on you. It silently searches your computer for usernames, passwords, and bank card information saved in your internet browsers. It then tries to send this private information to a cybercriminal.",
            "behaviors": [
                {"time": "0.1s", "activity": "Process executed with administrative privileges", "category": "Execution", "severity": "Info"},
                {"time": "0.6s", "activity": "Accessing Google Chrome User Data folder: Chrome\\User Data\\Default\\Login Data", "category": "Credential Access", "severity": "Critical"},
                {"time": "1.2s", "activity": "Accessing Mozilla Firefox profile database logins.json", "category": "Credential Access", "severity": "Critical"},
                {"time": "1.9s", "activity": "Injecting code into standard svchost.exe system process", "category": "Defense Evasion", "severity": "High"},
                {"time": "2.6s", "activity": "Establishing connection to exfiltration server: fast-downloads.ru", "category": "C2 Connection", "severity": "High"},
                {"time": "3.3s", "activity": "Sending harvested credentials and cookies via HTTP POST to exfil URL", "category": "C2 Connection", "severity": "Critical"}
            ],
            "mitre_techniques": ["T1003", "T1041", "T1562"],
            "iocs": [
                {"type": "IP", "value": "91.219.29.44"},
                {"type": "Domain", "value": "fast-downloads.ru"},
                {"type": "URL", "value": "https://fast-downloads.ru/upload.php"},
                {"type": "Email", "value": "exfil@blackhat-hacker.com"}
            ]
        },
        "RAT": {
            "category": "Remote Access Trojan (RAT)",
            "threat_level": "Critical",
            "base_score": 90,
            "description": "A remote access backdoor enabling unauthorized system configuration, command execution, and interactive control.",
            "beginner_explanation": "This file acts like a backdoor into your computer. It creates a secret passageway that allows an attacker from the internet to log into your machine, run commands, view your screen, and control your system from anywhere in the world.",
            "behaviors": [
                {"time": "0.1s", "activity": "Process spawned via Windows Command Prompt", "category": "Execution", "severity": "Info"},
                {"time": "0.7s", "activity": "Creating persistent Scheduled Task 'SystemUpdater' to run at startup", "category": "Persistence", "severity": "High"},
                {"time": "1.3s", "activity": "Spawning PowerShell with encoded script execution payload", "category": "Execution", "severity": "Critical"},
                {"time": "2.2s", "activity": "Dumping local Security Accounts Manager (SAM) database registries", "category": "Credential Access", "severity": "Critical"},
                {"time": "3.0s", "activity": "Establishing permanent reverse-shell connection to 104.244.42.1 on port 4444", "category": "C2 Connection", "severity": "Critical"},
                {"time": "3.8s", "activity": "Awaiting commands from external threat actor", "category": "C2 Connection", "severity": "Medium"}
            ],
            "mitre_techniques": ["T1059", "T1547", "T1003", "T1041", "T1053"],
            "iocs": [
                {"type": "IP", "value": "104.244.42.1"},
                {"type": "Domain", "value": "dynamic-c2.ddns.net"},
                {"type": "URL", "value": "http://dynamic-c2.ddns.net:4444/shell"},
                {"type": "File Hash", "value": "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92"}
            ]
        },
        "Adware": {
            "category": "Adware / PUP",
            "threat_level": "Medium",
            "base_score": 45,
            "description": "A potentially unwanted program (PUP) that modifies browser configurations and routes traffic through ad networks.",
            "beginner_explanation": "This file is a piece of adware. It is not designed to steal passwords or encrypt files, but it will modify your web browser settings to show you unwanted, annoying pop-up advertisements and redirect your searches to sketchy websites.",
            "behaviors": [
                {"time": "0.1s", "activity": "Installer launched by user", "category": "Execution", "severity": "Info"},
                {"time": "0.9s", "activity": "Modifying browser default home page registry configuration settings", "category": "Persistence", "severity": "Medium"},
                {"time": "1.7s", "activity": "Installing suspicious web helper extension into Google Chrome config path", "category": "Persistence", "severity": "Medium"},
                {"time": "2.5s", "activity": "Initiating connection to telemetry tracking server: ad-clicker-network.xyz", "category": "C2 Connection", "severity": "Low"}
            ],
            "mitre_techniques": ["T1547", "T1041"],
            "iocs": [
                {"type": "Domain", "value": "ad-clicker-network.xyz"},
                {"type": "URL", "value": "http://ad-clicker-network.xyz/track?id=992"}
            ]
        },
        "Clean": {
            "category": "Benign",
            "threat_level": "Low",
            "base_score": 10,
            "description": "A verified clean binary that utilizes standard OS APIs and shows no indicators of suspicious behavior.",
            "beginner_explanation": "Good news! This file is clean and completely safe to use. It doesn't perform any malicious actions and uses standard system routines just like any normal app or document on your computer.",
            "behaviors": [
                {"time": "0.1s", "activity": "Process launched successfully", "category": "Execution", "severity": "Info"},
                {"time": "0.5s", "activity": "Loading standard operating system system libraries (kernel32.dll, user32.dll)", "category": "Execution", "severity": "Info"},
                {"time": "1.0s", "activity": "Reading application config file", "category": "Discovery", "severity": "Info"},
                {"time": "1.8s", "activity": "Application completed execution cycle cleanly", "category": "Execution", "severity": "Info"}
            ],
            "mitre_techniques": [],
            "iocs": []
        }
    }
    
    return profiles[profile_type]

def get_profile_by_filename(filename, sha256_hash):
    filename_lower = filename.lower()
    
    # Keyword detection (has highest priority)
    if any(k in filename_lower for k in ["wannacry", "ransomware", "crypt", "ransom", "locker"]):
        return "Ransomware"
    elif any(k in filename_lower for k in ["keylogger", "stealer", "creds", "password", "spyware", "credential"]):
        return "Spyware"
    elif any(k in filename_lower for k in ["backdoor", "rat", "shell", "trojan", "payload", "cmd"]):
        return "RAT"
    elif any(k in filename_lower for k in ["adware", "coupon", "toolbar", "clicker", "popup"]):
        return "Adware"
    elif any(k in filename_lower for k in ["clean", "resume", "report", "invoice", "notes", "calc", "valid"]):
        return "Clean"
    
    # Safe Extensions: benign image, media, text and standard document file formats should ALWAYS default to Clean
    _, ext = os.path.splitext(filename_lower)
    benign_exts = [
        ".jpg", ".jpeg", ".png", ".gif", ".svg", ".bmp", ".ico", ".tiff", ".webp", # Images
        ".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt", ".odt", # Documents
        ".txt", ".log", ".csv", ".ini", ".cfg", ".json", ".xml", ".yaml", ".yml", # Texts
        ".mp3", ".wav", ".ogg", ".mp4", ".avi", ".mkv", ".mov", ".wmv", # Media
        ".zip", ".rar", ".7z", ".tar", ".gz" # Archives
    ]
    if ext in benign_exts:
        return "Clean"
        
    # Standard executable or script extensions can be mapped deterministically if not matching key indicators
    exec_exts = [".exe", ".dll", ".sys", ".js", ".vbs", ".bat", ".ps1", ".scr", ".jar", ".msi"]
    if ext not in exec_exts:
        # Non-executable, non-script unknown extensions default to Clean for safety
        return "Clean"
        
    # Deterministic mapping only for unknown executable payloads
    val = int(sha256_hash[:4], 16) % 5
    profiles_list = ["Clean", "Ransomware", "Spyware", "RAT", "Adware"]
    return profiles_list[val]
