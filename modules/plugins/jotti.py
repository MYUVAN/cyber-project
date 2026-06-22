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
    Simulates querying Jotti's Malware Scan multi-engine lookup database.
    """
    is_test = "fake_hash" in sha256_hash
    
    if is_test or vt_result:
        profile_type = get_dynamic_profile_type(filename, sha256_hash, vt_result)
        
        if vt_result:
            vt_score = vt_result.get("risk_score", 0)
            vt_family = vt_result.get("detected_malware_family", "None")
            
            if vt_score > 80:
                detections = {"Bitdefender": "Malicious", "Kaspersky": "Malicious", "Sophos": "Malicious", "ClamAV": "Malicious", "F-Secure": "Malicious"}
                confidence = "98%"
            elif vt_score > 50:
                detections = {"Bitdefender": "Malicious", "Kaspersky": "Malicious", "Sophos": "Malicious", "ClamAV": "Clean", "F-Secure": "Malicious"}
                confidence = "85%"
            elif vt_score > 30:
                detections = {"Bitdefender": "Malicious", "Kaspersky": "Clean", "Sophos": "Suspicious", "ClamAV": "Clean", "F-Secure": "Malicious"}
                confidence = "65%"
            elif vt_score > 10:
                detections = {"Bitdefender": "Clean", "Kaspersky": "Clean", "Sophos": "Suspicious", "ClamAV": "Clean", "F-Secure": "Suspicious"}
                confidence = "35%"
            else:
                detections = {"Bitdefender": "Clean", "Kaspersky": "Clean", "Sophos": "Clean", "ClamAV": "Clean", "F-Secure": "Clean"}
                confidence = "0%"
                
            labels = [f"{vt_family}.Scan", f"Trojan.{vt_family}"] if vt_score > 0 else []
            jotti_score = vt_score
        else:
            confidence = "98%" if profile_type == "Ransomware" else ("85%" if profile_type == "Spyware" else ("94%" if profile_type == "RAT" else ("65%" if profile_type == "Adware" else "0%")))
            jotti_score = 98 if profile_type == "Ransomware" else (82 if profile_type == "Spyware" else (92 if profile_type == "RAT" else (45 if profile_type == "Adware" else 0)))
            labels = []
            
        if profile_type == "Ransomware":
            if not vt_result:
                detections = {"Bitdefender": "Malicious", "Kaspersky": "Malicious", "Sophos": "Malicious", "ClamAV": "Malicious", "F-Secure": "Malicious"}
                labels = ["WannaCry.Ransom", "Win32.Crypt.Wanna"]
            indicators = ["Shadow copy deletion commands", "High entropy packing patterns"]
        elif profile_type == "Spyware":
            if not vt_result:
                detections = {"Bitdefender": "Malicious", "Kaspersky": "Malicious", "Sophos": "Malicious", "ClamAV": "Clean", "F-Secure": "Malicious"}
                labels = ["AgentTesla.Spy", "Spyware.AgentTesla"]
            indicators = ["Injects standard services", "Browses login credentials caches"]
        elif profile_type == "RAT":
            if not vt_result:
                detections = {"Bitdefender": "Malicious", "Kaspersky": "Malicious", "Sophos": "Malicious", "ClamAV": "Malicious", "F-Secure": "Malicious"}
                labels = ["NjRAT.Backdoor", "Trojan.NjRAT.Generic"]
            indicators = ["Scheduled startup task hooks", "PowerShell shell code scripts"]
        elif profile_type == "Adware":
            if not vt_result:
                detections = {"Bitdefender": "Suspicious", "Kaspersky": "Clean", "Sophos": "Suspicious", "ClamAV": "Clean", "F-Secure": "Suspicious"}
                labels = ["OpenCandy.Adware", "PUP.OpenCandy.Generic"]
            indicators = ["Homepage overrides in registry", "Telemetry tracking callouts"]
        else:
            if not vt_result:
                detections = {"Bitdefender": "Clean", "Kaspersky": "Clean", "Sophos": "Clean", "ClamAV": "Clean", "F-Secure": "Clean"}
            indicators = []

        return {
            "detection_results": detections,
            "suspicious_indicators": indicators,
            "malware_labels": labels,
            "detection_confidence": confidence,
            "risk_score": jotti_score
        }

    return None
