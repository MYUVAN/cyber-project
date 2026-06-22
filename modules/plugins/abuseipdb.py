import os
import re
import requests
from modules.dynamic_analysis import get_profile_by_filename, simulate_dynamic_analysis

def run(filename, sha256_hash, vt_result=None):
    """
    Queries AbuseIPDB API for IP reputations if key is configured,
    otherwise fallback to simulated data.
    """
    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if api_key:
        try:
            # 1. Get the dynamic analysis profile to extract IPs
            dynamic_data = simulate_dynamic_analysis(filename, sha256_hash)
            behaviors = dynamic_data.get("behaviors", [])
            iocs = dynamic_data.get("iocs", [])
            
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            ips = set()
            
            # Extract IPs from IOCs
            for ioc in iocs:
                if ioc.get("type") == "IP":
                    val = ioc.get("value")
                    if val and val != "127.0.0.1":
                        ips.add(val)
            
            # Extract IPs from behaviors
            for b in behaviors:
                activity = b.get("activity", "")
                matches = re.findall(ip_pattern, activity)
                for ip in matches:
                    if ip != "127.0.0.1":
                        ips.add(ip)
            
            # If no IPs are detected, return clean profile
            if not ips:
                return {
                    "malicious_ip_addresses": [],
                    "confidence_score": 0,
                    "country": "N/A",
                    "isp": "N/A",
                    "usage_type": "N/A",
                    "total_reports": 0,
                    "threat_category": "None",
                    "risk_score": 0
                }
                
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                "Accept": "application/json",
                "Key": api_key
            }
            
            malicious_ips = []
            max_score_info = None
            max_score = -1
            
            # Query reputation for each IP
            for ip in sorted(list(ips)):
                params = {
                    "ipAddress": ip,
                    "maxAgeInDays": "90"
                }
                response = requests.get(url, headers=headers, params=params, timeout=10)
                if response.status_code == 200:
                    data = response.json().get("data", {})
                    confidence = data.get("abuseConfidenceScore", 0)
                    if confidence > 0:
                        malicious_ips.append(ip)
                    
                    if confidence > max_score:
                        max_score = confidence
                        max_score_info = {
                            "confidence_score": confidence,
                            "country": data.get("countryName") or data.get("countryCode") or "N/A",
                            "isp": data.get("isp") or "N/A",
                            "usage_type": data.get("usageType") or "N/A",
                            "total_reports": data.get("totalReports", 0),
                            "threat_category": "Hacking / Botnet / C2" if confidence > 50 else "Suspicious IP Activity",
                            "risk_score": confidence
                        }
                else:
                    response.raise_for_status()
                    
            if max_score_info is not None:
                max_score_info["malicious_ip_addresses"] = malicious_ips
                return max_score_info
            else:
                return {
                    "malicious_ip_addresses": [],
                    "confidence_score": 0,
                    "country": "N/A",
                    "isp": "N/A",
                    "usage_type": "N/A",
                    "total_reports": 0,
                    "threat_category": "None",
                    "risk_score": 0
                }
        except Exception:
            pass

    # Simulated Fallback (offline testing)
    profile_type = get_profile_by_filename(filename, sha256_hash)
    
    if profile_type == "Ransomware":
        return {
            "malicious_ip_addresses": ["185.220.101.5"],
            "confidence_score": 100,
            "country": "Netherlands",
            "isp": "Tor Exit Node Provider",
            "usage_type": "Data Center/Web Hosting/Transit",
            "total_reports": 4520,
            "threat_category": "Hacking / Botnet / C2",
            "risk_score": 100
        }
    elif profile_type == "Spyware":
        return {
            "malicious_ip_addresses": ["91.219.29.44"],
            "confidence_score": 92,
            "country": "Russian Federation",
            "isp": "Private Hosting Network",
            "usage_type": "Data Center / Transit",
            "total_reports": 1824,
            "threat_category": "Spyware Exfiltration / Keylogging",
            "risk_score": 92
        }
    elif profile_type == "RAT":
        return {
            "malicious_ip_addresses": ["104.244.42.1"],
            "confidence_score": 95,
            "country": "United States",
            "isp": "Cloud Provider Hosting",
            "usage_type": "Data Center",
            "total_reports": 2405,
            "threat_category": "Reverse Backdoor Shell Connection",
            "risk_score": 95
        }
    elif profile_type == "Adware":
        return {
            "malicious_ip_addresses": ["104.22.42.99"],
            "confidence_score": 35,
            "country": "United States",
            "isp": "CDN Provider",
            "usage_type": "Content Delivery Network",
            "total_reports": 110,
            "threat_category": "Adware / Telemetry Logging",
            "risk_score": 35
        }
    else: # Clean
        return {
            "malicious_ip_addresses": [],
            "confidence_score": 0,
            "country": "N/A",
            "isp": "N/A",
            "usage_type": "N/A",
            "total_reports": 0,
            "threat_category": "None",
            "risk_score": 0
        }

