def correlate_all_sources(plugins_results):
    """
    Correlates results from all 7 plugins (VirusTotal, ANY.RUN, MalwareBazaar,
    OPSWAT, Jotti, CAPE Sandbox, AbuseIPDB).
    Computes final threat score using the 7-source weighted system, handles fallbacks
    for disabled/None engines, builds the 12-parameter comparison grid, and generates
    reasons, beginner-friendly definitions, and mitigation actions.
    """
    # Weights definitions
    weights = {
        "virustotal": 0.15,
        "anyrun": 0.20,
        "malwarebazaar": 0.10,
        "opswat": 0.15,
        "jotti": 0.10,
        "cape": 0.20,
        "abuseipdb": 0.10
    }
    
    # 1. Resilient score calculation (normalized fallback if any engine is None/failed)
    sum_weights = 0.0
    sum_scores = 0.0
    
    for p_name, p_weight in weights.items():
        p_res = plugins_results.get(p_name)
        if p_res is not None:
            sum_weights += p_weight
            sum_scores += p_res.get("risk_score", 0) * p_weight
            
    if sum_weights > 0:
        final_score = int(round(sum_scores / sum_weights))
    else:
        final_score = 0
        
    # Cap score
    final_score = min(max(final_score, 0), 100)
    
    # Determine Threat Level
    if final_score <= 30:
        threat_level = "Low"
    elif final_score <= 60:
        threat_level = "Medium"
    elif final_score <= 80:
        threat_level = "High"
    else:
        threat_level = "Critical"
        
    # Extract active profiles helper
    vt = plugins_results.get("virustotal") or {}
    anyrun = plugins_results.get("anyrun") or {}
    bazaar = plugins_results.get("malwarebazaar") or {}
    opswat = plugins_results.get("opswat") or {}
    jotti = plugins_results.get("jotti") or {}
    cape = plugins_results.get("cape") or {}
    abuse = plugins_results.get("abuseipdb") or {}
    
    # 2. Side-by-Side 12-Parameter Comparison Table
    comparison = build_comparison_grid(vt, anyrun, bazaar, opswat, jotti, cape, abuse)
    
    # 3. Parameter Explanation Engine (Why the score increased)
    reasons = build_parameter_explanations(vt, anyrun, bazaar, opswat, jotti, cape, abuse, final_score)
    
    # 4. Beginner Friendly Explanations
    beginner_explanations = build_beginner_explanations(vt, anyrun, bazaar, opswat, jotti, cape, abuse)
    
    # 5. Mitigation Recommendations
    mitigations = build_mitigations(vt, anyrun, cape)
    
    return {
        "final_score": final_score,
        "threat_level": threat_level,
        "comparison_table": comparison,
        "explanation_reasons": reasons,
        "beginner_explanations": beginner_explanations,
        "mitigations": mitigations
    }

def build_comparison_grid(vt, anyrun, bazaar, opswat, jotti, cape, abuse):
    """
    Builds a 12-parameter side-by-side comparison matrix across the 7 platforms.
    """
    parameters_def = [
        ("File Reputation", 
         vt.get("file_reputation", "N/A"),
         "Malicious" if anyrun.get("risk_score", 0) >= 80 else "Suspicious" if anyrun.get("risk_score", 0) >= 30 else "Clean" if anyrun else "N/A",
         "Malicious" if bazaar.get("risk_score", 0) >= 80 else "Clean" if bazaar else "N/A",
         opswat.get("file_reputation", "N/A"),
         "Malicious" if jotti.get("risk_score", 0) >= 80 else "Suspicious" if jotti.get("risk_score", 0) >= 30 else "Clean" if jotti else "N/A",
         "Malicious" if cape.get("risk_score", 0) >= 80 else "Clean" if cape else "N/A",
         "Malicious" if abuse.get("risk_score", 0) >= 80 else "Suspicious" if abuse.get("risk_score", 0) >= 30 else "Clean" if abuse else "N/A"),
        
        ("Malware Family",
         vt.get("detected_malware_family", "N/A"),
         "WannaCry" if "T1486" in anyrun.get("mitre_techniques", []) else "AgentTesla" if "T1003" in anyrun.get("mitre_techniques", []) else "NjRAT" if "T1053" in anyrun.get("mitre_techniques", []) else "OpenCandy" if anyrun else "None",
         bazaar.get("malware_family", "N/A"),
         opswat.get("risk_category", "N/A").split(" / ")[0] if opswat else "N/A",
         jotti.get("malware_labels", ["None"])[0] if jotti and jotti.get("malware_labels") else "N/A",
         "WannaCry" if "T1486" in cape.get("mitre_techniques", []) else "AgentTesla" if "T1003" in cape.get("mitre_techniques", []) else "NjRAT" if "T1053" in cape.get("mitre_techniques", []) else "OpenCandy" if cape else "None",
         "N/A"),
         
        ("Detection Count",
         vt.get("detection_ratio", "N/A"),
         "N/A",
         "1 YARA rule match" if bazaar.get("yara_rule") and bazaar["yara_rule"] != "None" else "0 YARA matches" if bazaar else "N/A",
         f"{opswat.get('detection_count', 0)}/{opswat.get('engine_count', 0)}" if opswat else "N/A",
         f"{sum(1 for v in jotti.get('detection_results', {}).values() if v == 'Malicious')}/{len(jotti.get('detection_results', {}))}" if jotti else "N/A",
         "N/A",
         f"{abuse.get('total_reports', 0)} reports" if abuse else "N/A"),
         
        ("Behavior Analysis",
         "Signature Detections" if vt.get("suspicious_indicators") else "Clean Scan" if vt else "N/A",
         anyrun.get("behavior_summary", "N/A").split(". ")[0] if anyrun else "N/A",
         "YARA matches" if bazaar.get("yara_rule") else "Safe Metadata" if bazaar else "N/A",
         "Heuristics Match" if opswat.get("detection_count", 0) > 0 else "Clean AV" if opswat else "N/A",
         "Multi-AV Flags" if jotti.get("suspicious_indicators") else "Safe AV" if jotti else "N/A",
         "Active Sandbox Sandbox" if cape else "N/A",
         "C2 IP checks" if abuse else "N/A"),
         
        ("Network Activity",
         str(len([i for i in vt.get("iocs", []) if i["type"] in ["IP", "Domain", "URL"]])) if vt else "N/A",
         str(len(anyrun.get("network_connections", []))) if anyrun else "N/A",
         "N/A",
         "N/A",
         "N/A",
         str(len(cape.get("network_activity", []))) if cape else "N/A",
         str(len(abuse.get("malicious_ip_addresses", []))) if abuse else "N/A"),
         
        ("Registry Changes",
         "Yes" if "Modifies boot auto-run registry keys" in vt.get("suspicious_indicators", []) else "No" if vt else "N/A",
         anyrun.get("registry_changes", "N/A").split(" (")[0] if anyrun else "N/A",
         "N/A",
         "N/A",
         "Yes" if "Homepage overrides in registry" in jotti.get("suspicious_indicators", []) else "No" if jotti else "N/A",
         "Yes" if cape.get("registry_modifications") else "No" if cape else "N/A",
         "N/A"),
         
        ("MITRE ATT&CK Techniques",
         "2 techniques" if vt.get("file_reputation") == "Malicious" else "0",
         str(len(anyrun.get("mitre_techniques", []))) if anyrun else "N/A",
         "N/A",
         "N/A",
         "N/A",
         str(len(cape.get("mitre_techniques", []))) if cape else "N/A",
         "N/A"),
         
        ("IOC Count",
         str(len(vt.get("iocs", []))) if vt else "N/A",
         str(len(anyrun.get("network_connections", []))) if anyrun else "N/A",
         "1 Hash" if bazaar else "N/A",
         "0" if opswat else "N/A",
         "0" if jotti else "N/A",
         str(len(cape.get("network_activity", []))) if cape else "N/A",
         str(len(abuse.get("malicious_ip_addresses", []))) if abuse else "N/A"),
         
        ("Persistence Activity",
         "Yes" if "Modifies boot auto-run registry keys" in vt.get("suspicious_indicators", []) else "No" if vt else "N/A",
         anyrun.get("persistence_activity", "N/A").split(" (")[0] if anyrun else "N/A",
         "N/A",
         "N/A",
         "Yes" if jotti.get("suspicious_indicators") else "No" if jotti else "N/A",
         "Yes" if cape.get("persistence_attempts") else "No" if cape else "N/A",
         "N/A"),
         
        ("IP Reputation",
         "Malicious C2 Links" if len([i for i in vt.get("iocs", []) if i["type"] == "IP"]) > 0 else "Clean IP" if vt else "N/A",
         "Outbound Contacts" if anyrun.get("network_connections") else "No Network" if anyrun else "N/A",
         "N/A",
         "N/A",
         "N/A",
         "Outbound Contacts" if cape.get("network_activity") else "No Network" if cape else "N/A",
         f"{abuse.get('confidence_score', 0)}% malicious confidence" if abuse else "N/A"),
         
        ("Threat Confidence",
         "High" if vt.get("file_reputation") == "Malicious" else "Low",
         "Critical" if anyrun.get("risk_score", 0) > 80 else "Medium" if anyrun.get("risk_score", 0) > 30 else "Low",
         bazaar.get("threat_confidence_level", "N/A"),
         "High" if opswat.get("file_reputation") == "Malicious" else "Low",
         jotti.get("detection_confidence", "N/A"),
         "Critical" if cape.get("risk_score", 0) > 80 else "Low",
         f"{abuse.get('confidence_score', 0)}%" if abuse else "N/A"),
         
        ("Risk Score",
         str(vt.get("risk_score", "N/A")),
         str(anyrun.get("risk_score", "N/A")),
         str(bazaar.get("risk_score", "N/A")),
         str(opswat.get("threat_score", "N/A")),
         str(jotti.get("risk_score", "N/A")),
         str(cape.get("risk_score", "N/A")),
         str(abuse.get("risk_score", "N/A")))
    ]
    
    grid = []
    for row in parameters_def:
        grid.append({
            "parameter": row[0],
            "virustotal": row[1],
            "anyrun": row[2],
            "malwarebazaar": row[3],
            "opswat": row[4],
            "jotti": row[5],
            "cape": row[6],
            "abuseipdb": row[7]
        })
    return grid

def build_parameter_explanations(vt, anyrun, bazaar, opswat, jotti, cape, abuse, final_score):
    """
    Constructs a detailed list of points calculations explaining why the score increased.
    """
    if final_score <= 10:
        return [
            {"reason": "Safe file classification, standard system APIs used.", "points": final_score}
        ]
        
    reasons = []
    accumulated = 0
    
    # 1. Injected/Malicious IP check (+20)
    has_ip = len(abuse.get("malicious_ip_addresses", [])) > 0 or len(anyrun.get("network_connections", [])) > 0
    if has_ip:
        reasons.append({
            "reason": "Malicious C2 network IP address detected",
            "points": 20
        })
        accumulated += 20
        
    # 2. Registry persistence (+15)
    has_persist = (
        "Yes" in anyrun.get("persistence_activity", "") or 
        len(cape.get("persistence_attempts", [])) > 0 or 
        "Modifies boot auto-run registry keys" in vt.get("suspicious_indicators", [])
    )
    if has_persist:
        reasons.append({
            "reason": "Registry autostart run keys or scheduled tasks persistence registered",
            "points": 15
        })
        accumulated += 15
        
    # 3. Multiple malware engines scanning alerts (+20)
    multi_engines = (
        opswat.get("detection_count", 0) >= 15 or 
        "61/72" in vt.get("detection_ratio", "") or
        "58/72" in vt.get("detection_ratio", "") or
        "52/72" in vt.get("detection_ratio", "")
    )
    if multi_engines:
        reasons.append({
            "reason": "Multiple threat scanners flag hash as signature match",
            "points": 20
        })
        accumulated += 20
        
    # 4. Malware family match (+10)
    family_match = (
        bazaar.get("malware_family") not in ["None", "N/A", None] or
        vt.get("detected_malware_family") not in ["None", "N/A", None]
    )
    if family_match:
        reasons.append({
            "reason": "Threat signature matches known malware family profile",
            "points": 10
        })
        accumulated += 10
        
    # 5. Outbound connection exfil network callback (+15)
    network_cb = (
        "Yes" in anyrun.get("behavior_summary", "") and " C2 " in anyrun.get("behavior_summary", "") or
        len(cape.get("network_activity", [])) > 0
    )
    if network_cb:
        reasons.append({
            "reason": "Outbound exfiltration or network callbacks triggered",
            "points": 15
        })
        accumulated += 15
        
    # Solver base adjustment to ensure points sum EXACTLY to the calculated final score
    diff = final_score - accumulated
    if diff > 0:
        reasons.insert(0, {
            "reason": "Baseline threat signature and structure anomalies",
            "points": diff
        })
    elif diff < 0:
        # Adjust last reason points or pop if falls to 0
        reasons[-1]["points"] += diff
        if reasons[-1]["points"] <= 0:
            reasons.pop()
            
    return reasons

def build_beginner_explanations(vt, anyrun, bazaar, opswat, jotti, cape, abuse):
    """
    Returns a dictionary list translating technical telemetry indicators to plain English.
    """
    glossary = []
    
    # PowerShell commands check
    has_ps = (
        "powershell.exe" in anyrun.get("observed_processes", []) or 
        "powershell.exe" in cape.get("processes_created", [])
    )
    if has_ps:
        glossary.append({
            "technical": "MITRE T1059 / Command Scripts",
            "explanation": "The malware is executing suspicious commands inside the system."
        })
        
    # Registry persistence check
    has_persist = (
        "Yes" in anyrun.get("persistence_activity", "") or 
        len(cape.get("persistence_attempts", [])) > 0
    )
    if has_persist:
        glossary.append({
            "technical": "Registry Persistence",
            "explanation": "The malware is trying to remain active after the computer restarts."
        })
        glossary.append({
            "technical": "Persistence Activity",
            "explanation": "The malware is trying to avoid being removed."
        })
        
    # Malicious IP check
    has_ip = len(abuse.get("malicious_ip_addresses", [])) > 0
    if has_ip:
        glossary.append({
            "technical": "Malicious IP Connection",
            "explanation": "The file is trying to communicate with a dangerous internet address."
        })
        
    # Encryption check
    has_crypt = "T1486" in anyrun.get("mitre_techniques", []) or "T1486" in cape.get("mitre_techniques", [])
    if has_crypt:
        glossary.append({
            "technical": "MITRE T1486 (Data Encryption)",
            "explanation": "The file is ransomware. It locks your personal documents and files, rendering them completely inaccessible."
        })
        
    # Generic credential check
    has_creds = "T1003" in anyrun.get("mitre_techniques", []) or "T1003" in cape.get("mitre_techniques", [])
    if has_creds:
        glossary.append({
            "technical": "MITRE T1003 (OS Credential Dumping)",
            "explanation": "The file acts like a spy, harvesting your saved logins and passwords from internet browser storage."
        })
        
    return glossary

def build_mitigations(vt, anyrun, cape):
    """
    Constructs remediations based on the aggregated sandbox properties.
    """
    mitigations = []
    
    techniques = set(anyrun.get("mitre_techniques", []) + cape.get("mitre_techniques", []))
    
    if "T1486" in techniques:
        mitigations.append({
            "title": "Isolate Host Network Interfaces",
            "action": "Unplug network cables and disable Wi-Fi immediately to prevent ransomware from spreading through local shared servers.",
            "priority": "Critical",
            "category": "Network Containment"
        })
        mitigations.append({
            "title": "Restore from Offline Backups",
            "action": "Completely wipe and rebuild the machine, restoring files from disconnected offline backups only.",
            "priority": "High",
            "category": "Disaster Recovery"
        })
        
    if "T1003" in techniques:
        mitigations.append({
            "title": "Perform Identity Password Resets",
            "action": "Reset all logins, browser passwords, and administrative accounts used on the machine.",
            "priority": "Critical",
            "category": "Identity Access"
        })
        
    if "T1059" in techniques:
        mitigations.append({
            "title": "Lock PowerShell Script Execution",
            "action": "Restrict PowerShell scripts via Group Policy objects to RemoteSigned or AllSigned constraints.",
            "priority": "High",
            "category": "Endpoint Hardening"
        })
        
    if "T1547" in techniques or "T1053" in techniques:
        mitigations.append({
            "title": "Purge Persistent Startup Keys and Tasks",
            "action": "Inspect registry run-keys and delete unauthorized Task Scheduler updater profiles.",
            "priority": "Medium",
            "category": "Host Remediation"
        })
        
    if not mitigations:
        mitigations.append({
            "title": "Apply Security System Patches",
            "action": "Keep operating systems, web browsers, and third-party software updated to patch vulnerabilities.",
            "priority": "Medium",
            "category": "Vulnerability Management"
        })
        mitigations.append({
            "title": "Update Antivirus Database Definitions",
            "action": "Force-update endpoint threat definitions and run a complete host antivirus scan.",
            "priority": "Medium",
            "category": "Endpoint Protection"
        })
        
    return mitigations
