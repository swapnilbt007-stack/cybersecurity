# cybersecurity
Interactive Linux Security Dashboard &amp; Auto-Fixer
A powerful, interactive Streamlit web application designed for Linux system administrators and security enthusiasts. This dashboard provides real-time monitoring of network connections, SSH intrusion detection, file integrity monitoring, and 1-click automated security remediations.

## ✨ Features

* **🌐 Active Services & Process Management:** View all listening ports and immediately terminate suspicious processes (PIDs) directly from the dashboard.
* **🚨 Intrusion Detection:** Parses `/var/log/auth.log` (or `secure`) to track failed SSH login attempts, mapping attacker IP addresses geographically.
* **📂 File Integrity Monitoring (FIM):** Establishes SHA-256 baseline hashes for critical files (`/etc/passwd`, `/etc/shadow`, etc.) and alerts you to unauthorized modifications.
* **⚙️ Vulnerability Audit & Auto-Fixer:** Checks system configurations (UFW status, SSH root login, IPv4 forwarding) and provides **1-Click Remediation** buttons to patch misconfigurations instantly. Also detects and applies apt security upgrades.

## ⚠️ Disclaimer
**Run with Caution:** This application executes system-level commands (`kill`, `ufw`, `systemctl`, `apt-get`) and modifies critical configuration files. It is intended for authorized use only. Ensure you understand the changes being made before clicking remediation buttons.

## 📋 Prerequisites

* A Linux-based operating system (Ubuntu/Debian recommended for `apt` and `ufw` compatibility).
* Python 3.8+ installed.
* `root` or `sudo` privileges (required to read logs, modify configs, and kill processes).

  
......usage......

install requirements first
pip install -r requirements.txt

run
streamlit run cybersecurity.py

Note: Access the dashboard via your browser at http://localhost:8501.
