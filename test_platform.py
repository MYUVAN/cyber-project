import unittest
import os
import json
import sqlite3
import shutil
from modules.static_analysis import analyze_file
from modules.dynamic_analysis import simulate_dynamic_analysis
from modules.risk_engine import calculate_risk_score
from modules.mitigation_engine import generate_mitigations
from modules.report_generator import generate_pdf_report
from modules.plugin_manager import run_all_plugins
from modules.unified_correlation_engine import correlate_all_sources
from app import app

class TestMalwarePlatform(unittest.TestCase):
    def setUp(self):
        # Create a mock temporary file for static analysis testing
        self.temp_file = "test_malware_sample.exe"
        with open(self.temp_file, "wb") as f:
            f.write(b"MZ" + b"\x00" * 100) # Mock executable header
            
    def tearDown(self):
        if os.path.exists(self.temp_file):
            os.remove(self.temp_file)
            
    def test_static_analysis(self):
        res = analyze_file(self.temp_file, self.temp_file)
        self.assertEqual(res["filename"], self.temp_file)
        self.assertEqual(res["extension"], ".exe")
        self.assertTrue(any("executable file extension" in ind for ind in res["indicators"]))
        self.assertEqual(res["static_risk"], "Medium")
        
    def test_dynamic_analysis_profile(self):
        # WannaCry profile
        res_ransom = simulate_dynamic_analysis("wannacry.exe", "fake_hash")
        self.assertEqual(res_ransom["category"], "Ransomware")
        self.assertEqual(res_ransom["threat_level"], "Critical")
        self.assertIn("T1486", res_ransom["mitre_techniques"])
        
        # Clean profile
        res_clean = simulate_dynamic_analysis("clean_resume.pdf", "fake_hash")
        self.assertEqual(res_clean["category"], "Benign")
        self.assertEqual(res_clean["threat_level"], "Low")
        
    def test_risk_engine(self):
        # Test strict math formula requirements
        # PowerShell (+20), Registry Autostart (+20) -> Score 40 (Medium)
        static_data = {"is_known_threat": False, "extension": ".exe"}
        dynamic_data = {"mitre_techniques": ["T1059", "T1547"]}
        res = calculate_risk_score(static_data, dynamic_data)
        self.assertEqual(res["score"], 40)
        self.assertEqual(res["level"], "Medium")
        
        # Known threat (+30), PowerShell (+20), Registry Autostart (+20), Network (+20), Credential (+10) -> Score 100 (Critical)
        static_known = {"is_known_threat": True, "extension": ".exe"}
        dynamic_known = {"mitre_techniques": ["T1059", "T1547", "T1041", "T1003"]}
        res_known = calculate_risk_score(static_known, dynamic_known)
        self.assertEqual(res_known["score"], 100)
        self.assertEqual(res_known["level"], "Critical")

        # Test get_beginner_explanation directly
        from modules.risk_engine import get_beginner_explanation
        self.assertIn("Low", get_beginner_explanation(30))
        self.assertIn("Medium", get_beginner_explanation(50))
        self.assertIn("High", get_beginner_explanation(75))
        self.assertIn("Critical", get_beginner_explanation(90))
        
    def test_all_plugins_execution(self):
        # Test individual plugins directly
        from modules.plugins import virustotal, anyrun, malwarebazaar, opswat, jotti, cape, abuseipdb
        
        vt_res = virustotal.run("wannacry.exe", "fake_hash")
        self.assertEqual(vt_res["risk_score"], 95)
        self.assertEqual(vt_res["detected_malware_family"], "WannaCry")
        
        any_res = anyrun.run("wannacry.exe", "fake_hash")
        self.assertEqual(any_res["risk_score"], 100)
        self.assertIn("T1486", any_res["mitre_techniques"])
        
        bazaar_res = malwarebazaar.run("wannacry.exe", "fake_hash")
        self.assertEqual(bazaar_res["risk_score"], 95)
        
        opswat_res = opswat.run("wannacry.exe", "fake_hash")
        self.assertEqual(opswat_res["threat_score"], 98)
        
        jotti_res = jotti.run("wannacry.exe", "fake_hash")
        self.assertEqual(jotti_res["risk_score"], 98)
        
        cape_res = cape.run("wannacry.exe", "fake_hash")
        self.assertEqual(cape_res["risk_score"], 98)
        
        abuse_res = abuseipdb.run("wannacry.exe", "fake_hash")
        self.assertEqual(abuse_res["risk_score"], 100)

    def test_plugin_manager_caching_and_run(self):
        # Test running all plugins via manager
        res = run_all_plugins("wannacry.exe", "fake_hash_123", force_reload=True)
        self.assertEqual(len(res), 7)
        self.assertEqual(res["virustotal"]["risk_score"], 95)
        self.assertEqual(res["abuseipdb"]["risk_score"], 100)

    def test_correlation_engine_weighted_scoring(self):
        # 1. Full plugins success scenario
        plugin_results = {
            "virustotal": {"risk_score": 95, "file_reputation": "Malicious", "detection_ratio": "61/72"},
            "anyrun": {"risk_score": 100, "mitre_techniques": ["T1486"]},
            "malwarebazaar": {"risk_score": 100, "malware_family": "WannaCry"},
            "opswat": {"risk_score": 95, "threat_score": 95, "file_reputation": "Malicious"},
            "jotti": {"risk_score": 90, "malware_labels": ["WannaCry"]},
            "cape": {"risk_score": 95, "mitre_techniques": ["T1486"]},
            "abuseipdb": {"risk_score": 85, "malicious_ip_addresses": ["1.1.1.1"]}
        }
        
        corr = correlate_all_sources(plugin_results)
        # Expected: 95*0.15 + 100*0.20 + 100*0.10 + 95*0.15 + 90*0.10 + 95*0.20 + 85*0.10 = 95.0
        self.assertEqual(corr["final_score"], 95)
        self.assertEqual(corr["threat_level"], "Critical")
        
        # 2. Resiliency scenario: Jotti and AbuseIPDB failed (None)
        resilient_results = plugin_results.copy()
        resilient_results["jotti"] = None
        resilient_results["abuseipdb"] = None
        
        corr_resilient = correlate_all_sources(resilient_results)
        # Remaining weights sum = 0.80
        # Weighted sum = 95*0.15 + 100*0.20 + 100*0.10 + 95*0.15 + 95*0.20 = 77.5
        # Expected normalized score = round(77.5 / 0.8) = 97
        self.assertEqual(corr_resilient["final_score"], 97)
        
        # Check comparison grid size & headers
        comp_table = corr["comparison_table"]
        self.assertEqual(len(comp_table), 12) # 12 specific parameters
        self.assertEqual(comp_table[0]["virustotal"], "Malicious")
        
        # Check explanation points sum to final score exactly
        reason_pts = sum(r["points"] for r in corr["explanation_reasons"])
        self.assertEqual(reason_pts, 95)

    def test_mitigation_engine(self):
        mitigations = generate_mitigations(["T1486", "T1003"])
        titles = [m["title"] for m in mitigations]
        self.assertIn("Isolate Host Immediately", titles)
        self.assertIn("Reset Local and Domain Credentials", titles)
        
    def test_report_generation(self):
        file_data = {
            "id": 999,
            "filename": "test_ransomware.exe",
            "hash": "5e883f89a24a1195973410bc31460d2d31408b067f18a514d2e7ff2b32269a2d",
            "upload_date": "2026-06-16 12:00:00",
            "risk_score": 95,
            "file_size": 1024,
            "malware_category": "Ransomware",
            "description": "Mock ransomware",
            "beginner_explanation": "This locks your files.",
            "behaviors": [{"time": "0.1s", "activity": "Spawned process", "category": "Execution", "severity": "Info"}],
            "static_indicators": ["Suspicious extension"]
        }
        file_data["vt"] = {"file_reputation": "Malicious", "risk_score": 95}
        file_data["anyrun"] = {"risk_score": 100}
        file_data["malwarebazaar"] = {"risk_score": 100}
        file_data["opswat"] = {"threat_score": 95}
        file_data["jotti"] = {"risk_score": 90}
        file_data["cape"] = {"risk_score": 95}
        file_data["abuseipdb"] = {"risk_score": 85}
        file_data["correlation"] = {
            "final_score": 95,
            "comparison_table": [
                {"parameter": "File Reputation", "virustotal": "Malicious", "anyrun": "Malicious", "malwarebazaar": "Malicious", "opswat": "Malicious", "jotti": "Malicious", "cape": "Malicious", "abuseipdb": "Malicious"}
            ],
            "explanation_reasons": [{"reason": "Test reason", "points": 95}],
            "beginner_explanations": [{"technical": "Test tech", "explanation": "Test explain"}],
            "mitigations": [{"priority": "High", "title": "Test mitigation", "action": "Do something"}]
        }
        iocs = [("IP", "1.1.1.1")]
        mitre_mappings = [{
            "technique_id": "T1486",
            "technique_name": "Data Encrypted for Impact",
            "technique_description": "Encrypts data",
            "beginner_explanation": "Locks files"
        }]
        mitigations = [{
            "title": "Isolate",
            "action": "Unplug",
            "priority": "Critical",
            "category": "Network"
        }]
        
        test_reports_dir = os.path.join(os.path.dirname(__file__), "test_reports")
        os.makedirs(test_reports_dir, exist_ok=True)
        
        pdf_name = generate_pdf_report(file_data, iocs, mitre_mappings, mitigations, test_reports_dir)
        pdf_path = os.path.join(test_reports_dir, pdf_name)
        
        self.assertTrue(os.path.exists(pdf_path))
        
        # Cleanup
        if os.path.exists(test_reports_dir):
            shutil.rmtree(test_reports_dir)
            
    def test_flask_routing(self):
        client = app.test_client()
        response = client.get("/login")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"MALWARE SYSTEM", response.data)

    def test_registration_and_login_analyst(self):
        client = app.test_client()
        import uuid
        test_username = f"analyst_{uuid.uuid4().hex[:6]}"
        
        # Test registration
        response = client.post("/register", data={
            "username": test_username,
            "password": "password123",
            "confirm_password": "password123"
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Registration successful", response.data)
        
        # Test login as new analyst
        response = client.post("/login", data={
            "username": test_username,
            "password": "password123"
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Access granted", response.data)

    def test_seeded_credentials(self):
        client = app.test_client()
        
        # Test login as kamalesh
        response = client.post("/login", data={
            "username": "kamalesh",
            "password": "Kamalesh@2006"
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Access granted", response.data)
        
        # Log out
        client.get("/logout")

    def test_upload_file(self):
        client = app.test_client()
        
        # Login first as kamalesh
        client.post("/login", data={
            "username": "kamalesh",
            "password": "Kamalesh@2006"
        }, follow_redirects=True)
        
        # Prepare a mock file to upload
        from io import BytesIO
        data = {
            'file': (BytesIO(b"MZ" + b"\x00" * 100), 'test_upload_file.exe')
        }
        
        # Post the upload
        response = client.post("/upload", data=data, content_type='multipart/form-data', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Malware Behavior Diagnostics", response.data)
        self.assertNotIn(b"Error compiling diagnostics", response.data)



if __name__ == "__main__":
    unittest.main()
