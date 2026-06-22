import os
import requests
from modules.dynamic_analysis import get_profile_by_filename

def run(filename, sha256_hash, vt_result=None):
    """
    Queries OPSWAT MetaDefender Cloud API if a key is configured, otherwise fallback to simulated data.
    """
    api_key = os.environ.get("OPSWAT_API_KEY")
    if api_key and "fake_hash" not in sha256_hash:
        try:
            url = f"https://api.metadefender.com/v4/hash/{sha256_hash}"
            headers = {"apikey": api_key}
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                scan_results = data.get("scan_results", {})
                
                total_avs = scan_results.get("total_avs") or 35
                total_detected_avs = scan_results.get("total_detected_avs") or 0
                
                threat_score = int(round((total_detected_avs / total_avs) * 100)) if total_avs > 0 else 0
                
                file_reputation = "Clean"
                if total_detected_avs > 10:
                    file_reputation = "Malicious"
                elif total_detected_avs > 1:
                    file_reputation = "Suspicious"
                    
                risk_category = "None / Safe"
                if total_detected_avs > 0:
                    risk_category = "Malicious Binary"
                    scan_details = scan_results.get("scan_details", {})
                    for engine, result in scan_details.items():
                        threat_name = result.get("threat_name")
                        if threat_name:
                            risk_category = threat_name
                            break
                            
                detection_percentage = f"{(total_detected_avs / total_avs * 100):.1f}%" if total_avs > 0 else "0.0%"
                
                return {
                    "engine_count": total_avs,
                    "detection_count": total_detected_avs,
                    "threat_score": threat_score,
                    "file_reputation": file_reputation,
                    "risk_category": risk_category,
                    "detection_percentage": detection_percentage,
                    "risk_score": threat_score
                }
        except Exception:
            pass
        return None

    # Simulated Fallback for tests (if fake_hash is present)
    if "fake_hash" in sha256_hash:
        profile_type = get_profile_by_filename(filename, sha256_hash)
        engine_count = 35
        
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

    return None
