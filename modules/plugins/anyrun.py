from modules.dynamic_analysis import get_profile_by_filename

def run(filename, sha256_hash):
    """
    Simulates querying the ANY.RUN sandbox API.
    """
    profile_type = get_profile_by_filename(filename, sha256_hash)
    
    if profile_type == "Ransomware":
        return {
            "observed_processes": [filename, "cmd.exe", "powershell.exe", "vssadmin.exe"],
            "powershell_activity": "Yes (invoked to delete volume shadow backups)",
            "registry_changes": "Yes (added run keys for startup auto-run)",
            "persistence_activity": "Yes (HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run)",
            "network_connections": ["185.220.101.5", "onion-gateway.net"],
            "file_modifications": "Yes (encrypted doc/xls files, wrote README ransom note)",
            "mitre_techniques": ["T1059", "T1547", "T1041", "T1486"],
            "behavior_summary": "Process spawns PowerShell command interpreter to purge local shadow backups. Modifies registry persistence. Establishes encrypted connections to external C2 networks and rapidly encrypts local files.",
            "risk_score": 100
        }
    elif profile_type == "Spyware":
        return {
            "observed_processes": [filename, "svchost.exe"],
            "powershell_activity": "No",
            "registry_changes": "No",
            "persistence_activity": "No",
            "network_connections": ["91.219.29.44", "fast-downloads.ru"],
            "file_modifications": "Yes (read Chrome Login Data and Firefox logins.json profiles)",
            "mitre_techniques": ["T1003", "T1041", "T1562"],
            "behavior_summary": "Process injects malicious hooks into svchost.exe system process. Scans browser data files to steal saved credentials and passwords. Exfiltrates sensitive credentials via HTTP POST queries to external web servers.",
            "risk_score": 80
        }
    elif profile_type == "RAT":
        return {
            "observed_processes": [filename, "schtasks.exe", "powershell.exe", "cmd.exe"],
            "powershell_activity": "Yes (ran Base64 encoded startup payload script)",
            "registry_changes": "Yes (registered new startup task in Task Scheduler)",
            "persistence_activity": "Yes (created scheduled task 'SystemUpdater' to run on startup)",
            "network_connections": ["104.244.42.1", "dynamic-c2.ddns.net"],
            "file_modifications": "Yes (SAM database registry dumping)",
            "mitre_techniques": ["T1059", "T1547", "T1003", "T1041", "T1053"],
            "behavior_summary": "Backdoor installer scripts register a persistent scheduled task to launch payload on boot. Initiates obfuscated script engines, extracts credential database tables, and establishes interactive reverse-shell Command & Control link.",
            "risk_score": 92
        }
    elif profile_type == "Adware":
        return {
            "observed_processes": [filename, "chrome.exe"],
            "powershell_activity": "No",
            "registry_changes": "Yes (default browser homepages and extensions modified)",
            "persistence_activity": "Yes (modified browser startup properties)",
            "network_connections": ["ad-clicker-network.xyz"],
            "file_modifications": "Yes (modified Chrome Preferences files)",
            "mitre_techniques": ["T1547", "T1041"],
            "behavior_summary": "Installer application modifies registry values to hijack default search engine and homepages. Injects telemetry components and makes ongoing web connections to ad delivery servers.",
            "risk_score": 50
        }
    else: # Clean
        return {
            "observed_processes": [filename],
            "powershell_activity": "No",
            "registry_changes": "No",
            "persistence_activity": "No",
            "network_connections": [],
            "file_modifications": "No",
            "mitre_techniques": [],
            "behavior_summary": "Execution terminated successfully with standard clean exit code. No persistence modifications or outbound connections observed.",
            "risk_score": 0
        }
