import os
from modules.dynamic_analysis import get_profile_by_filename

def run(filename, sha256_hash):
    """
    Simulates querying the VirusTotal API.
    """
    profile_type = get_profile_by_filename(filename, sha256_hash)
    _, ext = os.path.splitext(filename.lower())
    
    file_type_map = {
        ".exe": "Win32 EXE",
        ".dll": "Win32 DLL",
        ".js": "JavaScript Script",
        ".vbs": "VBScript Script",
        ".bat": "Windows Batch File",
        ".ps1": "Windows PowerShell Script",
        ".scr": "Windows Screen Saver",
        ".jar": "Java Archive",
        ".msi": "Windows Installer Package",
        ".pdf": "PDF Document",
        ".docx": "Microsoft Word Document",
        ".xlsx": "Microsoft Excel Spreadsheet",
        ".zip": "ZIP Archive"
    }
    file_type = file_type_map.get(ext, "Unknown File Binary")
    
    if profile_type == "Ransomware":
        return {
            "file_reputation": "Malicious",
            "detection_ratio": "61/72",
            "file_type": file_type,
            "hash_reputation": "Malicious",
            "suspicious_indicators": [
                "Process spawned from temp folder",
                "Attempts to delete volume shadow copies",
                "High entropy / packed sections",
                "Modifies boot auto-run registry keys"
            ],
            "detected_malware_family": "WannaCry",
            "threat_level": "Critical",
            "iocs": [
                {"type": "IP", "value": "185.220.101.5"},
                {"type": "Domain", "value": "onion-gateway.net"},
                {"type": "URL", "value": "http://onion-gateway.net/handshake"}
            ],
            "risk_score": 95
        }
    elif profile_type == "Spyware":
        return {
            "file_reputation": "Malicious",
            "detection_ratio": "52/72",
            "file_type": file_type,
            "hash_reputation": "Malicious",
            "suspicious_indicators": [
                "Accesses web browser database folders",
                "Injects into svchost.exe system process",
                "Contains hardcoded exfiltration URL patterns"
            ],
            "detected_malware_family": "AgentTesla",
            "threat_level": "High",
            "iocs": [
                {"type": "IP", "value": "91.219.29.44"},
                {"type": "Domain", "value": "fast-downloads.ru"},
                {"type": "URL", "value": "https://fast-downloads.ru/upload.php"}
            ],
            "risk_score": 78
        }
    elif profile_type == "RAT":
        return {
            "file_reputation": "Malicious",
            "detection_ratio": "58/72",
            "file_type": file_type,
            "hash_reputation": "Malicious",
            "suspicious_indicators": [
                "Registers scheduled tasks for persistence",
                "Uses obfuscated or encoded PowerShell payloads",
                "Dumps Security Accounts Manager registry database"
            ],
            "detected_malware_family": "NjRAT",
            "threat_level": "Critical",
            "iocs": [
                {"type": "IP", "value": "104.244.42.1"},
                {"type": "Domain", "value": "dynamic-c2.ddns.net"},
                {"type": "URL", "value": "http://dynamic-c2.ddns.net:4444/shell"}
            ],
            "risk_score": 90
        }
    elif profile_type == "Adware":
        return {
            "file_reputation": "Suspicious",
            "detection_ratio": "18/72",
            "file_type": file_type,
            "hash_reputation": "Suspicious",
            "suspicious_indicators": [
                "Modifies internet browser homepage parameters",
                "Installs custom search bar extension settings",
                "Generates outbound tracking web callbacks"
            ],
            "detected_malware_family": "OpenCandy Adware",
            "threat_level": "Medium",
            "iocs": [
                {"type": "Domain", "value": "ad-clicker-network.xyz"},
                {"type": "URL", "value": "http://ad-clicker-network.xyz/track?id=992"}
            ],
            "risk_score": 45
        }
    else: # Clean
        return {
            "file_reputation": "Clean",
            "detection_ratio": "0/72",
            "file_type": file_type,
            "hash_reputation": "Safe",
            "suspicious_indicators": [],
            "detected_malware_family": "None",
            "threat_level": "Low",
            "iocs": [],
            "risk_score": 5
        }
