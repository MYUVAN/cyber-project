def get_beginner_explanation(score):
    if score <= 30:
        risk_level = "Low"
    elif score <= 60:
        risk_level = "Medium"
    elif score <= 80:
        risk_level = "High"
    else:
        risk_level = "Critical"
        
    if risk_level == "Low":
        return f"This file has a risk score of {score}/100, which is Low. The analysis shows that this file did not try to perform any harmful actions, modify system files, or connect to suspicious external servers. It behaves like a normal, clean file."
    elif risk_level == "Medium":
        return f"This file has a risk score of {score}/100, which is Medium. The file performs some administrative actions, like changing registry settings or checking network configurations. While this could be normal for configuration utilities, you should make sure you trust the source of this file."
    elif risk_level == "High":
        return f"This file has a risk score of {score}/100, which is High. It attempts to execute suspicious scripts (like PowerShell) or read sensitive browser data to steal passwords. It also tries to communicate with remote servers to report its findings. This behavior is typical of Trojans and spyware."
    else: # Critical
        return f"This file has a risk score of {score}/100, which is Critical. This file exhibits highly destructive actions: it attempts to lock (encrypt) your files (Ransomware), disable system protections (like Windows Defender), or establish full remote control connections. You should isolate this file and delete it immediately."

def calculate_risk_score(static_data, dynamic_data):
    """
    Calculates the threat score (0-100) and risk level using a rule-based engine.
    Matches the specific weight assignments:
    - Hash match = 30
    - PowerShell execution = 20
    - Registry persistence = 20
    - Network callback = 20
    - Credential access = 10
    """
    score = 0
    factors = []
    
    # 1. Check known signature / hash match
    if static_data.get("is_known_threat"):
        score += 30
        factors.append("File hash matches known threat signature (+30)")
        
    # 2. Check detected MITRE techniques
    techniques = dynamic_data.get("mitre_techniques", [])
    
    # PowerShell execution -> T1059
    if "T1059" in techniques:
        score += 20
        factors.append("PowerShell command interpreter execution (+20)")
        
    # Registry persistence -> T1547 / T1053
    if "T1547" in techniques or "T1053" in techniques:
        score += 20
        factors.append("Registry auto-start run keys or scheduled tasks (+20)")
        
    # Network callback -> T1041
    if "T1041" in techniques:
        score += 20
        factors.append("Data exfiltration or outbound C2 callback (+20)")
        
    # Credential access -> T1003
    if "T1003" in techniques:
        score += 10
        factors.append("OS credential dumping or password harvesting (+10)")
        
    # Cap score at 100 and floor at 0
    score = min(max(score, 0), 100)
    
    # If the file is completely benign and shows no behaviors, establish baseline clean score
    if len(techniques) == 0 and not static_data.get("is_known_threat"):
        ext = static_data.get("extension", "")
        if ext in [".exe", ".dll", ".scr"]:
            score = 10
            factors.append("Safe executable file with normal API activity")
        else:
            score = 5
            factors.append("Standard data file showing no anomalous behaviors")
            
    # Determine risk level
    if score <= 30:
        risk_level = "Low"
    elif score <= 60:
        risk_level = "Medium"
    elif score <= 80:
        risk_level = "High"
    else:
        risk_level = "Critical"
        
    # Beginner Explanation
    explanation = get_beginner_explanation(score)
        
    return {
        "score": score,
        "level": risk_level,
        "factors": factors,
        "explanation": explanation
    }

