# Vulnrecon - Enterprise Vulnerability Assessment Platform

![Python Version](https://img.shields.io/badge/Python-3.8%2B-green?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-purple?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-blue?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)


## 🔥 Features

- **Comprehensive Scanning**: Combines nuclei, subfinder, httpx, naabu, and dalfox
- **Smart Detection**: 1500+ nuclei templates for vulnerability detection
- **Professional Reports**: HTML and JSON output with severity classification
- **Performance Optimized**: Multi-threaded scanning with configurable timeouts

## 🚀 Quick Start

### Installation
```bash
git clone https://github.com/ubxroot/vulnrecon.git
cd vulnrecon
chmod +x install.sh
./install.sh
```
## Basic Usage
```bash
python vulnrecon.py -d example.com -o html
```
## 📚 Full Documentation
# Command Options
# Option	Description
-d	Target domain (required)
-o	Output format (json/html)
-q	Quiet mode (suppress output)
-t	Thread count (default: 10)

## Scan Types
# Full Assessment:
```bash
python vulnrecon.py -d example.com
```
# Subdomain Discovery:
```bash
python vulnrecon.py -d example.com --subdomains
```
# Port Scanning:
```bash
python vulnrecon.py -d example.com --ports
```

## 📊 Sample Report
https://i.imgur.com/JQZQZJQ.png

## 🌐 Supported Platforms
Linux (Full support)
macOS (Full support)
Windows (Basic functionality)

## ⚠️ Legal Disclaimer
This tool is for authorized security testing only. Unauthorized use is prohibited.

## 🤝 Contributing
Pull requests are welcome! See CONTRIBUTING.md for guidelines.

Developed with 🔒 by UBXROOT
