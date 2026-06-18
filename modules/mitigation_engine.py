def generate_mitigations(technique_ids):
    """
    Generates actionable cybersecurity mitigation recommendations
    based on the MITRE ATT&CK techniques identified in the analysis.
    """
    mitigations = []
    
    # Check for specific technique mappings
    if "T1486" in technique_ids: # Data Encrypted for Impact
        mitigations.append({
            "title": "Isolate Host Immediately",
            "action": "Disconnect the infected system from the local network (disconnect Ethernet and turn off Wi-Fi) immediately to prevent ransomware from spreading to shared folders or other network hosts.",
            "priority": "Critical",
            "category": "Network / Containment"
        })
        mitigations.append({
            "title": "Restore from Offline Backups",
            "action": "Wipe the infected workstation and rebuild the system. Restore files from safe, offline backups. Do not pay the ransom, as it does not guarantee decryption.",
            "priority": "High",
            "category": "Disaster Recovery"
        })
        
    if "T1003" in technique_ids: # OS Credential Dumping
        mitigations.append({
            "title": "Reset Local and Domain Credentials",
            "action": "Perform immediate password resets for all active user accounts and local administrator accounts on the system, as credentials may have been dumped from LSASS memory.",
            "priority": "Critical",
            "category": "Identity Access Management"
        })
        mitigations.append({
            "title": "Enable Windows Defender Credential Guard",
            "action": "Enable LSA protection and activate Windows Defender Credential Guard via Group Policy to prevent unauthorized processes from reading security memory.",
            "priority": "High",
            "category": "Endpoint Hardening"
        })
        
    if "T1059" in technique_ids: # Command and Scripting Interpreter (PowerShell)
        mitigations.append({
            "title": "Restrict PowerShell Execution Policy",
            "action": "Configure the PowerShell execution policy to 'RemoteSigned' or 'AllSigned' via Group Policy to block arbitrary script execution.",
            "priority": "High",
            "category": "Endpoint Hardening"
        })
        mitigations.append({
            "title": "Enable Script Block Logging",
            "action": "Enable PowerShell Script Block Logging and Transcription Logging in Group Policy. This creates audit trails of all PowerShell commands executed.",
            "priority": "Medium",
            "category": "Audit & Monitoring"
        })
        
    if "T1041" in technique_ids: # Exfiltration / Network Callback
        mitigations.append({
            "title": "Block Malicious IPs and Domains",
            "action": "Configure the perimeter firewall and web proxy servers to block outbound traffic to the identified IP addresses and domains.",
            "priority": "High",
            "category": "Network Security"
        })
        mitigations.append({
            "title": "Analyze Egress Traffic logs",
            "action": "Inspect netflow logs and firewall histories for anomalous outbound traffic from the infected host to evaluate how much data may have been exfiltrated.",
            "priority": "Medium",
            "category": "Incident Investigation"
        })
        
    if "T1562" in technique_ids: # Impair Defenses
        mitigations.append({
            "title": "Re-enable Local Security Defenses",
            "action": "Force-restart the Windows Defender Antivirus service. Audit security settings via active directory group policy objects to override local malicious registry tweaks.",
            "priority": "High",
            "category": "Endpoint Hardening"
        })
        
    if "T1547" in technique_ids or "T1053" in technique_ids: # Registry Persistence / Scheduled Tasks
        mitigations.append({
            "title": "Remove Persistence Registry Keys and Tasks",
            "action": "Delete the unauthorized startup registry keys in HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run or drop the scheduled tasks created in Windows Task Scheduler.",
            "priority": "Medium",
            "category": "Host Remediation"
        })
        
    # Baseline recommendations if no malicious techniques or clean file
    if len(mitigations) == 0:
        mitigations.append({
            "title": "Update Antivirus Signatures",
            "action": "Ensure that system antivirus signatures are updated to the latest versions to proactively protect the workstation.",
            "priority": "Medium",
            "category": "Endpoint Security"
        })
        mitigations.append({
            "title": "Patch Operating System & Applications",
            "action": "Apply the latest system operating patches and update third-party browser plugins to prevent vulnerability exploit scripts.",
            "priority": "Medium",
            "category": "Vulnerability Management"
        })
        
    return mitigations
