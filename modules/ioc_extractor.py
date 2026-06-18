import re
import sqlite3

def extract_and_store_iocs(file_id, profile_iocs, behaviors, db_path):
    """
    Extracts IOCs from the profile and scans execution logs using regex.
    Saves all unique IOCs to the SQLite database table 'ioc_database'.
    """
    ioc_list = []
    
    # 1. Load predefined profile IOCs
    for ioc in profile_iocs:
        ioc_list.append((ioc["type"], ioc["value"]))
        
    # 2. Regex scanners for dynamic log scans
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    # Simple URL pattern matching http/https targets
    url_pattern = r'https?://[a-zA-Z0-9./?=&_-]+'
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
    
    # Search within activities list for any matching patterns
    for b in behaviors:
        activity = b.get("activity", "")
        
        # Check IPs
        ips = re.findall(ip_pattern, activity)
        for ip in ips:
            # Avoid loopback interface if matched
            if ip != "127.0.0.1":
                ioc_list.append(("IP", ip))
                
        # Check URLs
        urls = re.findall(url_pattern, activity)
        for url in urls:
            ioc_list.append(("URL", url))
            
        # Check Emails
        emails = re.findall(email_pattern, activity)
        for email in emails:
            ioc_list.append(("Email", email))
            
    # Deduplicate indicators
    unique_iocs = []
    seen = set()
    for item in ioc_list:
        pair_key = (item[0], item[1])
        if pair_key not in seen:
            seen.add(pair_key)
            unique_iocs.append(item)
            
    # 3. Store in the SQLite Database under ioc_database
    if isinstance(db_path, str):
        conn = sqlite3.connect(db_path, timeout=30.0)
        should_close = True
    else:
        conn = db_path
        should_close = False
        
    cursor = conn.cursor()
    try:
        for ioc_type, ioc_value in unique_iocs:
            cursor.execute(
                "INSERT INTO ioc_database (file_id, ioc_type, ioc_value) VALUES (?, ?, ?)",
                (file_id, ioc_type, ioc_value)
            )
        if should_close:
            conn.commit()
    except Exception as e:
        if should_close:
            conn.rollback()
        raise e
    finally:
        if should_close:
            conn.close()
        
    return unique_iocs
