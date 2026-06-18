from modules.dynamic_analysis import get_profile_by_filename

def run(filename, sha256_hash):
    """
    Simulates querying AbuseIPDB for IP reputation indicators.
    """
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
            "malicious_ip_addresses": ["104.22.42.99"], # ad network IP
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
