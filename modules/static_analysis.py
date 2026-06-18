import hashlib
import os

def analyze_file(filepath, filename):
    """
    Simulates static analysis of an uploaded file.
    Calculates file hash, extracts extension and size, and provides static indicators.
    """
    hasher = hashlib.sha256()
    file_size = 0
    try:
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        file_size = os.path.getsize(filepath)
    except Exception:
        # Fallback if read error or if file is mock/removed
        hasher.update(filename.encode('utf-8'))
        file_size = 1024
        
    sha256_hash = hasher.hexdigest()
    _, ext = os.path.splitext(filename)
    ext = ext.lower()
    
    indicators = []
    suspicious_exts = ['.exe', '.js', '.vbs', '.bat', '.ps1', '.scr', '.jar', '.dll']
    document_exts = ['.pdf', '.docx', '.xlsx', '.zip']
    
    if ext in suspicious_exts:
        indicators.append(f"Suspicious executable file extension ({ext})")
    elif ext in document_exts:
        indicators.append(f"Document or archive extension ({ext}) - could contain macros or exploit scripts")
        
    if ext in suspicious_exts and file_size < 50 * 1024:
        indicators.append("Unusually small file size for executable - possible downloader or stager")
        
    # Predefined known malicious hashes for simulation purposes
    known_malicious_hashes = {
        "5e883f89a24a1195973410bc31460d2d31408b067f18a514d2e7ff2b32269a2d": "WannaCry Ransomware (Simulated)",
        "2f9547d6e6a17b07db3d8fcf533d1b329486c9d81d2e1bdf3226315263156291": "Keylogger / Credential Stealer (Simulated)",
        "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92": "Backdoor / Remote Access Trojan (Simulated)"
    }
    
    is_known_threat = False
    threat_name = "Unknown"
    
    if sha256_hash in known_malicious_hashes:
        is_known_threat = True
        threat_name = known_malicious_hashes[sha256_hash]
        indicators.append(f"MATCH: File hash matches known threat signature: {threat_name}")
        
    static_risk = "Low"
    if is_known_threat:
        static_risk = "Critical"
    elif ext in suspicious_exts:
        static_risk = "Medium"
    elif ext in document_exts:
        static_risk = "Low"
        
    return {
        "filename": filename,
        "extension": ext,
        "file_size_bytes": file_size,
        "file_size_formatted": format_size(file_size),
        "sha256": sha256_hash,
        "indicators": indicators,
        "static_risk": static_risk,
        "is_known_threat": is_known_threat,
        "threat_name": threat_name
    }

def format_size(size_bytes):
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
