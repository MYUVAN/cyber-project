import sqlite3
import json
import os

# Predefined MITRE ATT&CK technique registry for custom beginner explanations
MITRE_REGISTRY = {
    "T1059": {
        "name": "Command and Scripting Interpreter (PowerShell)",
        "description": "Adversaries may abuse command and scripting interpreters (specifically PowerShell) to execute malicious commands, scripts, and payloads.",
        "beginner_explanation": "This file uses hidden command-line scripts (PowerShell) to bypass security blocks and run commands without your knowledge."
    },
    "T1547": {
        "name": "Boot or Logon Autostart Execution (Registry Run Keys)",
        "description": "Adversaries may modify startup registry run keys or file locations to achieve automatic execution of payloads when the system boots up or users login.",
        "beginner_explanation": "This file changes your computer's startup registry settings so it launches automatically every time you turn on your computer."
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "description": "Adversaries may attempt to dump credentials, passwords, and hashes from system storage databases (e.g. LSASS process memory or SAM registry) to obtain administrator credentials.",
        "beginner_explanation": "This file attempts to extract and steal your saved usernames and passwords directly from your computer's memory storage."
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "description": "Adversaries may steal sensitive user data and exfiltrate it by sending it over an established command and control (C2) network tunnel.",
        "beginner_explanation": "This file gathers confidential information from your computer and uploads it secretly to an external server run by threat actors."
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "description": "Adversaries may encrypt user or system files to render them unusable and disrupt operations, typically accompanied by ransom demands.",
        "beginner_explanation": "This is a ransomware attack: it locks (encrypts) your photos, spreadsheets, and documents and demands a fee to unlock them."
    },
    "T1562": {
        "name": "Impair Defenses (Disable Security Tools)",
        "description": "Adversaries may disable local security monitoring tools, firewalls, or Windows Defender to execute payloads without logging detections.",
        "beginner_explanation": "This file tries to turn off Windows Defender or disable your firewalls to make it easier to run malicious activities undetected."
    },
    "T1053": {
        "name": "Scheduled Task/Job",
        "description": "Adversaries may abuse system scheduling utilities (like Windows Task Scheduler) to register periodic, repeating background executions of a payload.",
        "beginner_explanation": "This file sets up a hidden background timer task that forces the malware to run repeatedly at scheduled times."
    }
}

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "database", "mitre_attack_db.json")
_dynamic_registry = None

def get_technique_details(tech_id):
    """
    Looks up technique ID in the dynamic MITRE JSON database, 
    falling back to static registry.
    """
    global _dynamic_registry
    if _dynamic_registry is None:
        if os.path.exists(DB_PATH):
            try:
                with open(DB_PATH, "r", encoding="utf-8") as f:
                    _dynamic_registry = json.load(f).get("techniques", {})
            except Exception:
                _dynamic_registry = {}
        else:
            _dynamic_registry = {}
            
    # Try dynamic database first
    if tech_id in _dynamic_registry:
        return _dynamic_registry[tech_id]
        
    # Fallback to local registry
    if tech_id in MITRE_REGISTRY:
        return MITRE_REGISTRY[tech_id]
        
    return None

def map_and_store_mitre(file_id, technique_ids, db_path):
    """
    Looks up details for a list of MITRE technique IDs,
    maps them to definitions and beginner explanations,
    and writes them to the database (Firestore or SQLite).
    """
    mapped_techniques = []
    
    for tech_id in technique_ids:
        tech_data = get_technique_details(tech_id)
        if tech_data:
            # Resolve beginner explanation
            if tech_id in MITRE_REGISTRY:
                beginner_explanation = MITRE_REGISTRY[tech_id]["beginner_explanation"]
            else:
                name = tech_data.get("name", "Unknown Technique")
                desc = tech_data.get("description", "")
                first_sentence = desc.split(".")[0] + "." if desc else "No details available."
                first_sentence = first_sentence.replace("\n", " ").strip()
                beginner_explanation = f"Activity corresponds to standard MITRE technique '{name}'. Action: {first_sentence}"
                
            mapped_techniques.append({
                "technique_id": tech_id,
                "name": tech_data.get("name", "Unknown Technique"),
                "description": tech_data.get("description", ""),
                "beginner_explanation": beginner_explanation
            })
            
    # Write to database
    if hasattr(db_path, "collection"):
        # Firestore client integration
        file_doc = db_path.collection("uploaded_files").document(str(file_id)).get()
        user_id = file_doc.to_dict().get("user_id") if file_doc.exists else None
        
        for tech in mapped_techniques:
            db_path.collection("mitre_mapping").add({
                "file_id": str(file_id),
                "user_id": user_id,
                "technique_id": tech["technique_id"],
                "technique_name": tech["name"],
                "technique_description": tech["description"],
                "beginner_explanation": tech["beginner_explanation"]
            })
    else:
        # SQLite database
        if isinstance(db_path, str):
            conn = sqlite3.connect(db_path, timeout=30.0)
            should_close = True
        else:
            conn = db_path
            should_close = False
            
        cursor = conn.cursor()
        try:
            for tech in mapped_techniques:
                cursor.execute(
                    """
                    INSERT INTO mitre_mapping 
                    (file_id, technique_id, technique_name, technique_description, beginner_explanation) 
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (file_id, tech["technique_id"], tech["name"], tech["description"], tech["beginner_explanation"])
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
        
    return mapped_techniques

