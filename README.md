# 🛡️ Cyber Threat Analysis Platform

A powerful cybersecurity platform for malware analysis, threat intelligence, and incident reporting.

## Features

- 🔍 **Static & Dynamic Malware Analysis**
- 🌐 **Multi-Source Threat Intelligence** (VirusTotal, AbuseIPDB, MalwareBazaar, ANY.RUN, CAPE, Jotti, OPSWAT)
- 🧠 **MITRE ATT&CK Mapping**
- 📊 **Unified Correlation Engine**
- 📄 **Automated Incident Report Generation**
- 🔒 **User Authentication (Login/Register)**
- 📈 **Threat Dashboard & Visualizations**

## Project Structure

```
cyber-project/
├── app.py                  # Main Flask application
├── test_platform.py        # Platform test suite
├── modules/
│   ├── anyrun_analyzer.py
│   ├── correlation_engine.py
│   ├── dynamic_analysis.py
│   ├── ioc_extractor.py
│   ├── mitigation_engine.py
│   ├── mitre_mapper.py
│   ├── plugin_manager.py
│   ├── report_generator.py
│   ├── risk_engine.py
│   ├── static_analysis.py
│   ├── unified_correlation_engine.py
│   ├── virustotal_analyzer.py
│   └── plugins/
│       ├── abuseipdb.py
│       ├── anyrun.py
│       ├── cape.py
│       ├── jotti.py
│       ├── malwarebazaar.py
│       ├── opswat.py
│       └── virustotal.py
├── templates/              # HTML templates
├── static/
│   ├── css/
│   ├── js/
│   └── reports/
└── database/
```

## Setup

```bash
pip install flask requests
python app.py
```

## Usage

1. Register/Login to the platform
2. Upload a file or provide a hash for analysis
3. View threat intelligence results across multiple sources
4. Generate and download incident reports

## Tech Stack

- **Backend:** Python / Flask
- **Frontend:** HTML, CSS, JavaScript
- **Threat Intel APIs:** VirusTotal, AbuseIPDB, MalwareBazaar, ANY.RUN, CAPE, Jotti, OPSWAT
