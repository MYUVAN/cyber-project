from modules.mitigation_engine import generate_mitigations

def correlate_reports(vt_res, anyrun_res, internal_risk_res):
    """
    Correlates the results of VirusTotal, ANY.RUN, and Internal Analysis.
    Calculates final score: (VT * 0.4) + (ANY.RUN * 0.4) + (Internal * 0.2)
    Generates comparison table, reasons explanation list (sum of reasons points = final score),
    and beginner explanations list.
    """
    vt_score = vt_res.get("risk_score", 0)
    anyrun_score = anyrun_res.get("risk_score", 0)
    internal_score = internal_risk_res.get("score", 0)
    
    # Final Threat Score Formula
    final_score = int(round(vt_score * 0.4 + anyrun_score * 0.4 + internal_score * 0.2))
    final_score = min(max(final_score, 0), 100)
    
    # Threat Level Classification
    if final_score <= 30:
        threat_level = "Low"
    elif final_score <= 60:
        threat_level = "Medium"
    elif final_score <= 80:
        threat_level = "High"
    else:
        threat_level = "Critical"
        
    # Parameter Explanation Engine
    reasons = []
    
    # Check detections to attribute points dynamically
    # 1. PowerShell Activity
    has_powershell = False
    if "Yes" in anyrun_res.get("powershell_activity", "") or "T1059" in anyrun_res.get("mitre_techniques", []):
        reasons.append({"reason": "PowerShell execution detected (+20)", "points": 20})
        has_powershell = True
        
    # 2. Registry Persistence
    has_persistence = False
    if anyrun_res.get("persistence_activity", "No") != "No" or "T1547" in anyrun_res.get("mitre_techniques", []) or "T1053" in anyrun_res.get("mitre_techniques", []):
        reasons.append({"reason": "Registry persistence detected (+20)", "points": 20})
        has_persistence = True
        
    # 3. Suspicious Network Callback
    has_network = False
    if anyrun_res.get("network_connections") or vt_res.get("iocs") or "T1041" in anyrun_res.get("mitre_techniques", []):
        reasons.append({"reason": "Suspicious network communication detected (+15)", "points": 15})
        has_network = True
        
    # 4. Multiple MITRE Techniques
    has_multiple_mitre = False
    if len(anyrun_res.get("mitre_techniques", [])) >= 2:
        reasons.append({"reason": "Multiple MITRE ATT&CK techniques were detected (+15)", "points": 15})
        has_multiple_mitre = True
        
    # 5. File Reputation Malicious
    has_mal_reputation = False
    if vt_res.get("file_reputation") == "Malicious" or vt_res.get("hash_reputation") == "Malicious":
        reasons.append({"reason": "File reputation is malicious (+10)", "points": 10})
        has_mal_reputation = True
        
    # 6. Multiple IOCs Extracted
    has_multiple_iocs = False
    if len(vt_res.get("iocs", [])) >= 2 or len(anyrun_res.get("network_connections", [])) >= 2:
        reasons.append({"reason": "Multiple IOCs were extracted (+12)", "points": 12})
        has_multiple_iocs = True

    # Adjust the reasons points so the sum matches final_score exactly
    reason_pts_sum = sum(r["points"] for r in reasons)
    diff = final_score - reason_pts_sum
    if diff != 0:
        reasons.append({"reason": "Base signature and file extension heuristics", "points": diff})
        
    # Beginner Friendly Explanations
    beginner_explanations = []
    
    # Risk score translation first
    if final_score <= 30:
        score_desc = "This file did not try to perform any harmful actions and is considered safe."
    elif final_score <= 60:
        score_desc = "This file performs moderate administrative actions and should be used with caution."
    elif final_score <= 80:
        score_desc = "This file performs multiple suspicious activities and is considered highly dangerous."
    else:
        score_desc = "This file exhibits highly destructive actions (like ransomware or full backdoor control) and is extremely hazardous."
        
    beginner_explanations.append({
        "technical": f"Risk Score = {final_score}/100",
        "explanation": score_desc
    })
    
    if has_powershell:
        beginner_explanations.append({
            "technical": "PowerShell Execution",
            "explanation": "The malware is using Windows command tools to perform suspicious activities."
        })
    if has_persistence:
        beginner_explanations.append({
            "technical": "Registry Persistence",
            "explanation": "The malware is trying to stay active even after the computer restarts."
        })
    if has_network:
        beginner_explanations.append({
            "technical": "Network Callback",
            "explanation": "The malware is communicating with external servers."
        })
    if "T1059" in anyrun_res.get("mitre_techniques", []):
        beginner_explanations.append({
            "technical": "MITRE T1059 (Command Execution)",
            "explanation": "The malware is executing commands inside the system."
        })
        
    # Side-by-Side Comparison Table
    comparison_table = [
        {
            "parameter": "File Reputation",
            "virustotal": vt_res.get("file_reputation", "Undetected"),
            "anyrun": "Active Threat Observed" if anyrun_score > 30 else "No Threat Observed"
        },
        {
            "parameter": "Behavior Analysis",
            "virustotal": f"{len(vt_res.get('suspicious_indicators', []))} indicators flagged",
            "anyrun": anyrun_res.get("behavior_summary", "No behavior logs")
        },
        {
            "parameter": "Network Activity",
            "virustotal": f"{len(vt_res.get('iocs', []))} connections / indicators",
            "anyrun": f"{len(anyrun_res.get('network_connections', []))} active connections"
        },
        {
            "parameter": "Registry Activity",
            "virustotal": "Yes" if any("registry" in str(ind).lower() for ind in vt_res.get("suspicious_indicators", [])) else "No",
            "anyrun": anyrun_res.get("registry_changes", "No")
        },
        {
            "parameter": "IOC Count",
            "virustotal": str(len(vt_res.get("iocs", []))),
            "anyrun": str(len(anyrun_res.get("network_connections", [])))
        },
        {
            "parameter": "MITRE Techniques",
            "virustotal": "Mapped via Family" if vt_res.get("detected_malware_family") != "None" else "0",
            "anyrun": str(len(anyrun_res.get("mitre_techniques", [])))
        },
        {
            "parameter": "Risk Score",
            "virustotal": f"{vt_score}/100",
            "anyrun": f"{anyrun_score}/100"
        },
        {
            "parameter": "Malware Category",
            "virustotal": vt_res.get("detected_malware_family", "Clean"),
            "anyrun": "Malicious Payload" if anyrun_score > 30 else "Benign"
        },
        {
            "parameter": "Persistence Detection",
            "virustotal": "Yes" if any("persistence" in str(ind).lower() for ind in vt_res.get("suspicious_indicators", [])) else "No",
            "anyrun": anyrun_res.get("persistence_activity", "No")
        },
        {
            "parameter": "Suspicious Process Count",
            "virustotal": "N/A (Static)",
            "anyrun": str(len(anyrun_res.get("observed_processes", [])))
        }
    ]
    
    # Generate Mitigations dynamically
    tech_ids = anyrun_res.get("mitre_techniques", [])
    mitigations = generate_mitigations(tech_ids)
    
    return {
        "final_score": final_score,
        "threat_level": threat_level,
        "explanation_reasons": reasons,
        "beginner_explanations": beginner_explanations,
        "comparison_table": comparison_table,
        "mitigations": mitigations
    }
