import os
import json
import traceback

# Import independent plugin modules
from modules.plugins import virustotal
from modules.plugins import anyrun
from modules.plugins import malwarebazaar
from modules.plugins import opswat
from modules.plugins import jotti
from modules.plugins import cape
from modules.plugins import abuseipdb

CACHE_FILE = os.path.join(os.path.dirname(__file__), "..", "database", "threat_cache.json")

def load_cache():
    """Loads cached plugin results from disk."""
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_cache(cache_data):
    """Saves plugin results cache to disk."""
    os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump(cache_data, f, indent=4)
    except Exception:
        pass

def run_all_plugins(filename, file_hash, force_reload=False):
    """
    Executes all 7 threat intelligence plugins for the given file and hash.
    Uses cached values if available and not forced to reload.
    If a plugin raises an error, it is gracefully logged and skipped (set to None)
    so the system remains functional.
    """
    cache = load_cache()
    
    if not force_reload and file_hash in cache:
        return cache[file_hash]
        
    results = {}
    
    plugins_registry = {
        "virustotal": virustotal,
        "anyrun": anyrun,
        "malwarebazaar": malwarebazaar,
        "opswat": opswat,
        "jotti": jotti,
        "cape": cape,
        "abuseipdb": abuseipdb
    }
    
    for plugin_name, plugin_module in plugins_registry.items():
        try:
            # Execute individual plugin
            res = plugin_module.run(filename, file_hash)
            results[plugin_name] = res
        except Exception as e:
            # Graceful error handling - set to None if failed/unavailable
            print(f"[ERROR] Plugin '{plugin_name}' failed or is unavailable: {str(e)}")
            traceback.print_exc()
            results[plugin_name] = None
            
    # Cache results
    cache[file_hash] = results
    save_cache(cache)
    
    return results
