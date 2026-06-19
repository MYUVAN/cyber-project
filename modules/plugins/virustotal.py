import os
import requests
from modules.dynamic_analysis import get_profile_by_filename

def run(filename, sha256_hash, vt_result=None):
    """
    Queries the VirusTotal API if a key is configured, otherwise fallback to simulated data.
    """
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

    # Attempt to use the live VirusTotal API if a key is provided
    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if api_key:
        try:
            url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
            headers = {"x-apikey": api_key}
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json().get("data", {})
                attributes = data.get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                
                malicious = stats.get("malicious", 0)
                undetected = stats.get("undetected", 0)
                total = sum(stats.values()) if stats else 1
                
                # Popular threat label
                threat_classification = attributes.get("popular_threat_classification", {})
                suggested_label = threat_classification.get("suggested_threat_label", "Malicious Binary")
                
                # Risk score
                risk_score = int(round((malicious / total) * 100)) if total > 0 else 0
                
                reputation = "Clean"
                if malicious > 10:
                    reputation = "Malicious"
                elif malicious > 2:
                    reputation = "Suspicious"
                    
                # Suspicious indicators
                indicators = []
                # Check for crowdsourced yara results
                yara_results = attributes.get("crowdsourced_yara_results", [])
                for rule in yara_results:
                    rule_name = rule.get("rule_name")
                    if rule_name:
                        indicators.append(f"YARA: {rule_name}")
                if malicious > 0:
                    indicators.append(f"Flagged by {malicious} security vendors on VirusTotal")
                    
                if not indicators:
                    indicators = ["No major YARA rules flagged"] if reputation == "Clean" else ["High VirusTotal detection ratio"]

                # Extract IOCs if they exist in threat_intel (optional or empty)
                return {
                    "file_reputation": reputation,
                    "detection_ratio": f"{malicious}/{total}",
                    "file_type": file_type,
                    "hash_reputation": reputation,
                    "suspicious_indicators": indicators[:4],
                    "detected_malware_family": suggested_label,
                    "threat_level": "Critical" if risk_score > 80 else ("High" if risk_score > 60 else ("Medium" if risk_score > 30 else "Low")),
                    "iocs": [],
                    "risk_score": risk_score
                }
        except Exception:
            # Fallback to simulated logic if API fails or throws
            pass

    # Simulated Fallback (offline testing)
    profile_type = get_profile_by_filename(filename, sha256_hash)
    
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
