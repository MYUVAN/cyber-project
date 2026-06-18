import os

def simulate_anyrun_analysis(filename, sha256_hash):
    """
    Simulates ANY.RUN detonation analysis based on the file category/profile.
    Returns processes, powershell, registry, network connections, file modifications,
    MITRE techniques, and risk score.
    """
    profile_type = get_profile_type(filename, sha256_hash)
    
    if profile_type == "Ransomware":
        return {
            "observed_processes": ["wannacry.exe", "vssadmin.exe", "cmd.exe", "powershell.exe"],
            "powershell_activity": "Yes (invoked to delete volume shadow backups)",
            "registry_changes": "Yes (boot persistence keys modified)",
            "persistence_activity": "Yes (HKCU Registry Run Key modification)",
            "network_connections": ["185.220.101.5:443 (SSL Callback)", "onion-gateway.net:80"],
            "file_modifications": "524 files encrypted",
            "mitre_techniques": ["T1059", "T1547", "T1041", "T1486"],
            "behavior_summary": "Spawns vssadmin.exe to delete system backup shadow copies, and runs encryption routines on document directories.",
            "risk_score": 100
        }
    elif profile_type == "Spyware":
        return {
            "observed_processes": ["browser_passwords.exe", "svchost.exe (injected)"],
            "powershell_activity": "No",
            "registry_changes": "No",
            "persistence_activity": "No",
            "network_connections": ["91.219.29.44:80 (HTTP Exfil)"],
            "file_modifications": "12 browser files accessed",
            "mitre_techniques": ["T1003", "T1041", "T1562"],
            "behavior_summary": "Accesses Chrome and Firefox credential databases and initiates outbound HTTP exfiltration.",
            "risk_score": 80
        }
    elif profile_type == "RAT":
        return {
            "observed_processes": ["update_agent.exe", "schtasks.exe", "powershell.exe"],
            "powershell_activity": "Yes (invoked with encoded payload)",
            "registry_changes": "Yes (schtasks task registered)",
            "persistence_activity": "Yes (Scheduled Task 'SystemUpdater')",
            "network_connections": ["104.244.42.1:4444 (Reverse Shell)"],
            "file_modifications": "3 files created",
            "mitre_techniques": ["T1059", "T1547", "T1003", "T1041", "T1053"],
            "behavior_summary": "Registers auto-start scheduled task and connects reverse-shell payload back to C2 controller.",
            "risk_score": 90
        }
    elif profile_type == "Adware":
        return {
            "observed_processes": ["coupon_installer.exe", "rundll32.exe"],
            "powershell_activity": "No",
            "registry_changes": "Yes (browser defaults modified)",
            "persistence_activity": "Yes (HKCU startup key)",
            "network_connections": ["ad-clicker-network.xyz:80"],
            "file_modifications": "14 browser preference files modified",
            "mitre_techniques": ["T1547", "T1041"],
            "behavior_summary": "Injects advertising traffic scripts and changes default homepage configuration.",
            "risk_score": 40
        }
    else: # Clean / Benign
        return {
            "observed_processes": ["fiscal_invoice.docx", "explorer.exe"],
            "powershell_activity": "No",
            "registry_changes": "No",
            "persistence_activity": "No",
            "network_connections": [],
            "file_modifications": "0 files modified",
            "mitre_techniques": [],
            "behavior_summary": "Executes clean OS functions, loads system libraries, and terminates successfully.",
            "risk_score": 0
        }

def get_profile_type(filename, sha256_hash):
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
        
    _, ext = os.path.splitext(filename_lower)
    benign_exts = [
        ".jpg", ".jpeg", ".png", ".gif", ".svg", ".bmp", ".ico", ".tiff", ".webp",
        ".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt", ".odt",
        ".txt", ".log", ".csv", ".ini", ".cfg", ".json", ".xml", ".yaml", ".yml",
        ".mp3", ".wav", ".ogg", ".mp4", ".avi", ".mkv", ".mov", ".wmv",
        ".zip", ".rar", ".7z", ".tar", ".gz"
    ]
    if ext in benign_exts:
        return "Clean"
        
    exec_exts = [".exe", ".dll", ".sys", ".js", ".vbs", ".bat", ".ps1", ".scr", ".jar", ".msi"]
    if ext not in exec_exts:
        return "Clean"
        
    # Deterministic mapping fallback
    try:
        val = int(sha256_hash[:4], 16) % 5
    except Exception:
        val = 0
    profiles_list = ["Clean", "Ransomware", "Spyware", "RAT", "Adware"]
    return profiles_list[val]
