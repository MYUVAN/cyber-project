from modules.dynamic_analysis import get_profile_by_filename

def run(filename, sha256_hash):
    """
    Simulates querying Jotti's Malware Scan multi-engine lookup database.
    """
    profile_type = get_profile_by_filename(filename, sha256_hash)
    
    if profile_type == "Ransomware":
        return {
            "detection_results": {
                "Bitdefender": "Malicious", 
                "Kaspersky": "Malicious", 
                "Sophos": "Malicious", 
                "ClamAV": "Malicious", 
                "F-Secure": "Malicious"
            },
            "suspicious_indicators": ["Shadow copy deletion commands", "High entropy packing patterns"],
            "malware_labels": ["WannaCry.Ransom", "Win32.Crypt.Wanna"],
            "detection_confidence": "98%",
            "risk_score": 98
        }
    elif profile_type == "Spyware":
        return {
            "detection_results": {
                "Bitdefender": "Malicious", 
                "Kaspersky": "Malicious", 
                "Sophos": "Malicious", 
                "ClamAV": "Clean", 
                "F-Secure": "Malicious"
            },
            "suspicious_indicators": ["Injects standard services", "Browses login credentials caches"],
            "malware_labels": ["AgentTesla.Spy", "Spyware.AgentTesla"],
            "detection_confidence": "85%",
            "risk_score": 82
        }
    elif profile_type == "RAT":
        return {
            "detection_results": {
                "Bitdefender": "Malicious", 
                "Kaspersky": "Malicious", 
                "Sophos": "Malicious", 
                "ClamAV": "Malicious", 
                "F-Secure": "Malicious"
            },
            "suspicious_indicators": ["Scheduled startup task hooks", "PowerShell shell code scripts"],
            "malware_labels": ["NjRAT.Backdoor", "Trojan.NjRAT.Generic"],
            "detection_confidence": "94%",
            "risk_score": 92
        }
    elif profile_type == "Adware":
        return {
            "detection_results": {
                "Bitdefender": "Suspicious", 
                "Kaspersky": "Clean", 
                "Sophos": "Suspicious", 
                "ClamAV": "Clean", 
                "F-Secure": "Suspicious"
            },
            "suspicious_indicators": ["Homepage overrides in registry", "Telemetry tracking callouts"],
            "malware_labels": ["OpenCandy.Adware", "PUP.OpenCandy.Generic"],
            "detection_confidence": "65%",
            "risk_score": 45
        }
    else: # Clean
        return {
            "detection_results": {
                "Bitdefender": "Clean", 
                "Kaspersky": "Clean", 
                "Sophos": "Clean", 
                "ClamAV": "Clean", 
                "F-Secure": "Clean"
            },
            "suspicious_indicators": [],
            "malware_labels": [],
            "detection_confidence": "0%",
            "risk_score": 0
        }
