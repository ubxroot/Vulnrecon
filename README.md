# Vulnrecon - Enterprise Web Vulnerability & Reconnaissance Platform

![Python Version](https://img.shields.io/badge/Python-3.8%2B-green?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-purple?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-blue?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)


**Vulnrecon** is an enterprise-grade vulnerability assessment and reconnaissance tool combining deep security scanning with intelligent reconnaissance capabilities. Designed for penetration testers, blue teams, and security researchers.

---

## ✨ Features

- 🔍 **Comprehensive Vulnerability Scanning**
  - Security header analysis (HSTS, CSP, X-Content-Type)
  - Sensitive file exposure detection (.git, .env, config files)
  - Basic XSS and open redirect detection
  - SSL/TLS misconfiguration checks
  - CORS misconfiguration detection

- 🌐 **Advanced Reconnaissance**
  - Passive subdomain discovery via certificate transparency
  - Common port scanning (21, 22, 80, 443, etc.)
  - Directory and file brute-forcing
  - robots.txt analysis

- 📊 **Professional Reporting**
  - Rich terminal output with color-coded findings
  - Severity-based prioritization (High/Medium/Low/Info)
  - Detailed remediation guidance for each finding
  - JSON output support (coming soon)

- ⚡ **Performance Optimized**
  - Multi-threaded scanning engine
  - Configurable timeout and retry logic
  - Smart error handling and progress tracking

---

## 🚀 Installation

### Requirements
- Python 3.8+
- pip package manager

### Quick Setup
```
git clone https://github.com/ubxroot/vulnrecon.git
cd vulnrecon
pip install -r requirements.txt
```

---

## 💡 Basic Usage

* Run full scan against target
```
python vulnrecon.py scan example.com
```
* Scan with 10 concurrent threads
```
python vulnrecon.py scan https://example.com --threads 10
```
* Perform port scan only
```
python vulnrecon.py port-scan 192.168.1.1
```

---

## 🧰 Advanced Features

* Subdomain discovery mode
```
python vulnrecon.py subdomains example.com
```
* Custom port range scanning
```
python vulnrecon.py port-scan 192.168.1.1 --ports 21-443
```
* Save results to JSON
```
python vulnrecon.py scan example.com --output results.json
```

---

## 🌐 Supported Platforms

| Platform | Supported |
|----------|:---------:|
| Linux    |    ✅     |
| Windows  |    ✅     |
| macOS    |    ✅     |

---

## 🛡️ License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

This tool is intended for **authorized security testing** and **ethical hacking purposes** only. Unauthorized use against systems you don't own or have explicit permission to test is strictly prohibited.

---

*Developed with 🔒 by [UBXROOT](https://github.com/ubxroot) | [Report Issue](https://github.com/ubxroot/vulnrecon/issues)*
