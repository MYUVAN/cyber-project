import os

def simulate_vt_analysis(filename, sha256_hash):
    """
    Simulates VirusTotal report generation based on the file category/profile.
    Returns file reputation, detection ratio, indicators, malware family, and risk score.
    """
    profile_type = get_profile_type(filename, sha256_hash)
    
    if profile_type == "Ransomware":
        return {
            "file_reputation": "Malicious",
            "detection_ratio": "65/72",
            "file_type": "Win32 EXE",
            "hash_reputation": "Malicious",
            "suspicious_indicators": [
                "Shadow copy deletion detected",
                "Mass file renaming detected",
                "High entropy payload sections"
            ],
            "detected_malware_family": "WannaCry",
            "threat_level": "Critical",
            "iocs": ["185.220.101.5", "onion-gateway.net", "http://onion-gateway.net/handshake"],
            "risk_score": 95
        }
    elif profile_type == "Spyware":
        return {
            "file_reputation": "Malicious",
            "detection_ratio": "52/72",
            "file_type": "JavaScript Script",
            "hash_reputation": "Malicious",
            "suspicious_indicators": [
                "Local credential database access",
                "Browser password harvesting indicators"
            ],
            "detected_malware_family": "AgentTesla",
            "threat_level": "High",
            "iocs": ["91.219.29.44", "fast-downloads.ru", "https://fast-downloads.ru/upload.php"],
            "risk_score": 78
        }
    elif profile_type == "RAT":
        return {
            "file_reputation": "Malicious",
            "detection_ratio": "58/72",
            "file_type": "Win32 EXE",
            "hash_reputation": "Malicious",
            "suspicious_indicators": [
                "PowerShell reverse shell payload matching",
                "Auto-start registry persistence key found"
            ],
            "detected_malware_family": "AsyncRAT",
            "threat_level": "Critical",
            "iocs": ["104.244.42.1", "dynamic-c2.ddns.net"],
            "risk_score": 90
        }
    elif profile_type == "Adware":
        return {
            "file_reputation": "Suspicious",
            "detection_ratio": "18/72",
            "file_type": "MSI Installer",
            "hash_reputation": "Suspicious",
            "suspicious_indicators": [
                "Adware traffic injector signature",
                "Silent browser extension installer helper"
            ],
            "detected_malware_family": "Adware.Coupon",
            "threat_level": "Medium",
            "iocs": ["ad-clicker-network.xyz", "http://ad-clicker-network.xyz/track?id=992"],
            "risk_score": 45
        }
    else: # Clean / Benign
        return {
            "file_reputation": "Undetected",
            "detection_ratio": "0/72",
            "file_type": "Document (DOCX)",
            "hash_reputation": "Clean",
            "suspicious_indicators": [],
            "detected_malware_family": "None",
            "threat_level": "Low",
            "iocs": [],
            "risk_score": 10
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
