from modules.dynamic_analysis import get_profile_by_filename

def get_dynamic_profile_type(filename, sha256_hash, vt_result):
    if vt_result:
        reputation = vt_result.get("file_reputation", "Clean")
        family = (vt_result.get("detected_malware_family") or "").lower()
        
        if reputation in ["Malicious", "Suspicious"]:
            if any(k in family for k in ["ransom", "crypt", "locker"]):
                return "Ransomware"
            elif any(k in family for k in ["keylog", "stealer", "spy", "credential"]):
                return "Spyware"
            elif any(k in family for k in ["backdoor", "rat", "trojan"]):
                return "RAT"
            elif any(k in family for k in ["adware", "pup", "clicker"]):
                return "Adware"
            else:
                return "RAT"
        else:
            return "Clean"
    return get_profile_by_filename(filename, sha256_hash)

def run(filename, sha256_hash, vt_result=None):
    """
    Simulates executing a file inside CAPE Sandbox.
    """
    is_test = "fake_hash" in sha256_hash
    
    if is_test or vt_result:
        profile_type = get_dynamic_profile_type(filename, sha256_hash, vt_result)
        vt_score = vt_result.get("risk_score", 80) if vt_result else (98 if profile_type == "Ransomware" else (82 if profile_type == "Spyware" else (92 if profile_type == "RAT" else (45 if profile_type == "Adware" else 0))))
        
        if profile_type == "Ransomware":
            return {
                "processes_created": [filename, "cmd.exe", "powershell.exe", "vssadmin.exe"],
                "registry_modifications": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
                "persistence_attempts": ["Startup run key modified"],
                "network_activity": ["185.220.101.5", "onion-gateway.net"],
                "mitre_techniques": ["T1059", "T1547", "T1041", "T1486"],
                "suspicious_commands": ["vssadmin.exe delete shadows /all /quiet"],
                "risk_score": vt_score
            }
        elif profile_type == "Spyware":
            return {
                "processes_created": [filename, "svchost.exe"],
                "registry_modifications": [],
                "persistence_attempts": [],
                "network_activity": ["91.219.29.44", "fast-downloads.ru"],
                "mitre_techniques": ["T1003", "T1041", "T1562"],
                "suspicious_commands": ["Injecting svchost.exe memory space"],
                "risk_score": vt_score
            }
        elif profile_type == "RAT":
            return {
                "processes_created": [filename, "schtasks.exe", "powershell.exe", "cmd.exe"],
                "registry_modifications": ["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
                "persistence_attempts": ["Registers task updater system scheduled runs"],
                "network_activity": ["104.244.42.1", "dynamic-c2.ddns.net"],
                "mitre_techniques": ["T1059", "T1547", "T1003", "T1041", "T1053"],
                "suspicious_commands": ["schtasks.exe /create /tn SystemUpdater /tr update_agent.exe"],
                "risk_score": vt_score
            }
        elif profile_type == "Adware":
            return {
                "processes_created": [filename, "chrome.exe"],
                "registry_modifications": ["HKCU\\Software\\Google\\Chrome\\PreferenceMacs"],
                "persistence_attempts": ["Inject chrome extension hooks"],
                "network_activity": ["ad-clicker-network.xyz"],
                "mitre_techniques": ["T1547", "T1041"],
                "suspicious_commands": [],
                "risk_score": vt_score
            }
        else: # Clean
            return {
                "processes_created": [filename],
                "registry_modifications": [],
                "persistence_attempts": [],
                "network_activity": [],
                "mitre_techniques": [],
                "suspicious_commands": [],
                "risk_score": vt_score
            }

    return None
