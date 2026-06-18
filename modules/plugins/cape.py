from modules.dynamic_analysis import get_profile_by_filename

def run(filename, sha256_hash):
    """
    Simulates executing a file inside CAPE Sandbox.
    """
    profile_type = get_profile_by_filename(filename, sha256_hash)
    
    if profile_type == "Ransomware":
        return {
            "processes_created": [filename, "cmd.exe", "powershell.exe", "vssadmin.exe"],
            "registry_modifications": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
            "persistence_attempts": ["Startup run key modified"],
            "network_activity": ["185.220.101.5", "onion-gateway.net"],
            "mitre_techniques": ["T1059", "T1547", "T1041", "T1486"],
            "suspicious_commands": ["vssadmin.exe delete shadows /all /quiet"],
            "risk_score": 98
        }
    elif profile_type == "Spyware":
        return {
            "processes_created": [filename, "svchost.exe"],
            "registry_modifications": [],
            "persistence_attempts": [],
            "network_activity": ["91.219.29.44", "fast-downloads.ru"],
            "mitre_techniques": ["T1003", "T1041", "T1562"],
            "suspicious_commands": ["Injecting svchost.exe memory space"],
            "risk_score": 82
        }
    elif profile_type == "RAT":
        return {
            "processes_created": [filename, "schtasks.exe", "powershell.exe", "cmd.exe"],
            "registry_modifications": ["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
            "persistence_attempts": ["Registers task updater system scheduled runs"],
            "network_activity": ["104.244.42.1", "dynamic-c2.ddns.net"],
            "mitre_techniques": ["T1059", "T1547", "T1003", "T1041", "T1053"],
            "suspicious_commands": ["schtasks.exe /create /tn SystemUpdater /tr update_agent.exe"],
            "risk_score": 92
        }
    elif profile_type == "Adware":
        return {
            "processes_created": [filename, "chrome.exe"],
            "registry_modifications": ["HKCU\\Software\\Google\\Chrome\\PreferenceMacs"],
            "persistence_attempts": ["Inject chrome extension hooks"],
            "network_activity": ["ad-clicker-network.xyz"],
            "mitre_techniques": ["T1547", "T1041"],
            "suspicious_commands": [],
            "risk_score": 45
        }
    else: # Clean
        return {
            "processes_created": [filename],
            "registry_modifications": [],
            "persistence_attempts": [],
            "network_activity": [],
            "mitre_techniques": [],
            "suspicious_commands": [],
            "risk_score": 0
        }
