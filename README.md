# 🔥 WebRipper Pro - Ultimate Web Hacking Tool

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.0-red" alt="Version">
  <img src="https://img.shields.io/badge/License-EDUCATIONAL-blue" alt="License">
  <img src="https://img.shields.io/badge/Platform-Kali%20Linux-purple" alt="Platform">
  <img src="https://img.shields.io/badge/Python-3.8+-green" alt="Python">
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/Irfan430/xxpro/main/assets/banner_3d.gif" width="800" alt="WebRipper Pro 3D Banner">
</p>

## 🎯 Overview

**WebRipper Pro** is an advanced, all-in-one web penetration testing tool designed for security professionals and ethical hackers. It automates the process of vulnerability scanning, exploitation, and post-exploitation activities with a user-friendly interface.

> ⚠️ **WARNING**: This tool is for **EDUCATIONAL PURPOSES ONLY**. Unauthorized hacking is illegal!

## ✨ Features

### 🎨 3D Interactive Interface
- Terminal-based 3D ASCII art
- Color-coded vulnerability display
- Real-time scanning animations
- Progress bars and status indicators

### 🔍 Automated Scanning
- CMS detection (WordPress, Joomla, Drupal, etc.)
- Server fingerprinting
- Port and service enumeration
- Vulnerability assessment

### ⚡ Smart Exploitation
- Auto-exploit critical vulnerabilities
- One-click reverse shell deployment
- Database dumping and exfiltration
- Post-exploitation automation

### 📊 Reporting
- HTML/PDF report generation
- Vulnerability categorization
- Exploitation evidence collection
- Recommendations for remediation

## 🚀 Quick Start

### Installation on Kali Linux

```bash
# Clone the repository
git clone https://github.com/Irfan430/xxpro.git
cd xxpro

# Make scripts executable
chmod +x xpro.py install.sh

# Run installation
sudo ./install.sh

# Install Python dependencies
pip3 install -r requirements.txt
```

### Environment Setup for Kali Linux

```bash
# 1. Update Kali
sudo apt update && sudo apt upgrade -y

# 2. Install essential tools
sudo apt install -y python3-pip git curl wget

# 3. Set up virtual environment (optional but recommended)
python3 -m venv webripper-env
source webripper-env/bin/activate

# 4. Install WebRipper Pro
./install.sh
```

## 🎮 Usage Examples

### Example 1: Basic Scan
```bash
# Interactive mode
python3 xpro.py

# Or use the shortcut
webripper
```

### Example 2: Direct Attack
```bash
# Attack a WordPress site
python3 xpro.py -t http://target.com -s 1 --auto

# Attack a Joomla site
python3 xpro.py -t https://joomla-site.com -s 2
```

### Example 3: Mass Attack
```bash
# Create targets file
echo "http://target1.com" > targets.txt
echo "http://target2.com" >> targets.txt

# Run mass attack
python3 xpro.py -m targets.txt --auto
```

### Example 4: Custom Service
```bash
# Service types:
# 1=WordPress, 2=Joomla, 3=PHP, 4=E-commerce
# 5=Custom CMS, 6=Server, 7=Database, 8=API

python3 xpro.py -t http://custom-cms.com -s 5
```

## 📋 Service Types

| # | Service | Example Targets | Key Features |
|---|---------|-----------------|--------------|
| 1 | WordPress | blog.com, news.com | Plugin vulns, XML-RPC, User enum |
| 2 | Joomla | portal.com, cms.com | Component exploits, SQLi |
| 3 | PHP | app.com, login.com | LFI/RFI, File upload, XSS |
| 4 | E-commerce | shop.com, store.com | Payment bypass, Admin access |
| 5 | Custom CMS | custom.com, internal.com | Generic scanning, Brute force |
| 6 | Server | server.com, api.com | Port scanning, Service exploits |
| 7 | Database | db.com, mysql.com | SQL injection, Credential theft |
| 8 | API | api.target.com, rest.com | Endpoint discovery, Auth bypass |

## 🎨 3D Interface Preview

```
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║    ██████╗ ███████╗██████╗ ██████╗ ██╗██████╗ ███████╗  ║
║    ██╔══██╗██╔════╝██╔══██╗██╔══██╗██║██╔══██╗██╔════╝  ║
║    ██████╔╝█████╗  ██████╔╝██████╔╝██║██████╔╝█████╗    ║
║    ██╔══██╗██╔══╝  ██╔══██╗██╔═══╝ ██║██╔══██╗██╔══╝    ║
║    ██║  ██║███████╗██║  ██║██║     ██║██║  ██║███████╗  ║
║    ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝  ║
║                                                          ║
║              ULTIMATE WEB HACKING TOOL v2.0              ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
```

## ⚙️ Configuration

### Configuration File
Create `~/.webripper/config.json`:
```json
{
  "proxy": "http://127.0.0.1:8080",
  "threads": 10,
  "timeout": 30,
  "wordlist_path": "/usr/share/wordlists/",
  "auto_exploit": true,
  "save_reports": true,
  "report_format": "html"
}
```

### Environment Variables
```bash
export WEBRIPPER_PROXY="http://proxy:8080"
export WEBRIPPER_THREADS=20
export WEBRIPPER_DEBUG=true
```

## 📁 Project Structure

```
xxpro/
├── xpro.py                 # Main tool
├── install.sh             # Installation script
├── requirements.txt       # Python dependencies
├── legal_disclaimer.txt   # Legal warning
├── README.md             # This file
├── modules/              # Attack modules
│   ├── scanner.py       # Scanning module
│   ├── exploit.py       # Exploitation module
│   └── report.py        # Reporting module
├── wordlists/           # Custom wordlists
├── reports/             # Generated reports
└── logs/               # Activity logs
```

## 🛡️ Legal Disclaimer

### ⚠️ IMPORTANT WARNING
```text
THIS TOOL IS FOR EDUCATIONAL PURPOSES ONLY!

- Only test systems you own or have written permission to test
- Unauthorized access to computer systems is illegal
- Violators can face imprisonment, fines, and criminal charges
- The developers are not responsible for misuse
```

### ✅ Legal Use Cases
1. **Penetration Testing** - With client authorization
2. **Security Research** - In controlled environments
3. **CTF Competitions** - Organized events
4. **Education** - Classroom demonstrations
5. **Self-testing** - Your own servers and applications

### ❌ Illegal Use Cases
1. Hacking without permission
2. Data theft or destruction
3. Website defacement
4. DDoS attacks
5. Spreading malware

## 🔧 Troubleshooting

### Common Issues

**Issue 1**: Python module errors
```bash
# Reinstall dependencies
pip3 install --upgrade -r requirements.txt
```

**Issue 2**: Tool not found
```bash
# Add to PATH
export PATH=$PATH:$(pwd)
```

**Issue 3**: Permission denied
```bash
# Run as root (Kali Linux)
sudo python3 xpro.py
```

**Issue 4**: Missing wordlists
```bash
# Download wordlists
sudo apt install wordlists
cd /usr/share/wordlists
sudo git clone https://github.com/danielmiessler/SecLists.git
```

### Kali Linux Specific Setup

```bash
# Full environment setup for Kali
#!/bin/bash

# Update system
sudo apt update && sudo apt full-upgrade -y

# Install Python and pip
sudo apt install -y python3 python3-pip python3-venv

# Install hacking tools
sudo apt install -y nmap sqlmap nikto gobuster wpscan hydra

# Create virtual environment
python3 -m venv ~/webripper_env
source ~/webripper_env/bin/activate

# Install WebRipper Pro
git clone https://github.com/Irfan430/xxpro.git
cd xxpro
pip3 install -r requirements.txt
chmod +x xpro.py
sudo ln -s $(pwd)/xpro.py /usr/local/bin/webripper

echo "Setup complete! Run 'webripper' to start."
```

## 📈 Advanced Usage

### Custom Modules
```python
# Create custom attack module in modules/
from xpro import WebRipperPro

class CustomAttack:
    def __init__(self, target):
        self.target = target
    
    def execute(self):
        # Your custom attack logic
        pass
```

### API Integration
```python
import requests
from xpro import Scanner

scanner = Scanner("http://target.com")
results = scanner.scan()
print(results.vulnerabilities)
```

### Automation Script
```bash
#!/bin/bash
# automate_scan.sh

TARGETS=("$@")
for target in "${TARGETS[@]}"; do
    echo "Scanning $target"
    python3 xpro.py -t "$target" -s 3 --auto
    sleep 5
done
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

### Code Style
- Follow PEP 8 guidelines
- Add comments for complex logic
- Include error handling
- Write unit tests for new features

## 📄 License

**EDUCATIONAL USE ONLY**

This tool is provided for educational purposes. The developers are not responsible for any misuse or damage caused by this tool. Users are solely responsible for obeying all applicable laws.

## 🌟 Star History

[![Star History Chart](https://api.star-history.com/svg?repos=Irfan430/xxpro&type=Date)](https://star-history.com/#Irfan430/xxpro&Date)

## 📞 Support

- **GitHub Issues**: [Report bugs](https://github.com/Irfan430/xxpro/issues)
- **Email**: security-research@example.com
- **Discord**: [Join community](https://discord.gg/example)

## 🙏 Acknowledgments

- Kali Linux Team
- OWASP Community
- Security Researchers Worldwide
- Open Source Tool Developers

---

<p align="center">
  <b>Remember: With great power comes great responsibility!</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Stay-Legal-green" alt="Stay Legal">
  <img src="https://img.shields.io/badge/Hack-Responsibly-blue" alt="Hack Responsibly">
  <img src="https://img.shields.io/badge/Report-Vulnerabilities-yellow" alt="Report Vulnerabilities">
</p>
```