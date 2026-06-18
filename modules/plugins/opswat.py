from modules.dynamic_analysis import get_profile_by_filename

def run(filename, sha256_hash):
    """
    Simulates scanning a file with OPSWAT MetaDefender multi-engine scanner.
    """
    profile_type = get_profile_by_filename(filename, sha256_hash)
    engine_count = 35 # Standard number of AV engines scanned in OPSWAT Cloud
    
    if profile_type == "Ransomware":
        detection_count = 33
        threat_score = 98
        file_reputation = "Malicious"
        risk_category = "Ransomware / Cryptor"
    elif profile_type == "Spyware":
        detection_count = 28
        threat_score = 82
        file_reputation = "Malicious"
        risk_category = "Spyware / Password Stealer"
    elif profile_type == "RAT":
        detection_count = 31
        threat_score = 92
        file_reputation = "Malicious"
        risk_category = "Remote Access Trojan"
    elif profile_type == "Adware":
        detection_count = 12
        threat_score = 48
        file_reputation = "Suspicious"
        risk_category = "Potentially Unwanted Application"
    else: # Clean
        detection_count = 0
        threat_score = 0
        file_reputation = "Clean"
        risk_category = "None / Safe"
        
    detection_percentage = f"{(detection_count / engine_count * 100):.1f}%" if detection_count > 0 else "0.0%"
    
    return {
        "engine_count": engine_count,
        "detection_count": detection_count,
        "threat_score": threat_score,
        "file_reputation": file_reputation,
        "risk_category": risk_category,
        "detection_percentage": detection_percentage,
        "risk_score": threat_score
    }
