#!/bin/bash
# WebRipper Pro Installation Script
# For Kali Linux / Debian-based systems

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${RED}"
cat << "EOF"
╔══════════════════════════════════════════════════════════╗
║      ██╗    ██╗███████╗██████╗ ██████╗ ██╗██████╗ ███████╗██████╗     ║
║      ██║    ██║██╔════╝██╔══██╗██╔══██╗██║██╔══██╗██╔════╝██╔══██╗    ║
║      ██║ █╗ ██║█████╗  ██████╔╝██████╔╝██║██████╔╝█████╗  ██████╔╝    ║
║      ██║███╗██║██╔══╝  ██╔══██╗██╔═══╝ ██║██╔══██╗██╔══╝  ██╔══██╗    ║
║      ╚███╔███╔╝███████╗██║  ██║██║     ██║██║  ██║███████╗██║  ██║    ║
║       ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝    ║
║                ULTIMATE WEB HACKING TOOL v2.0                 ║
║                     By WormGPT 😈                              ║
╚══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] This script must be run as root!${NC}"
   echo -e "${YELLOW}[*] Use: sudo ./install.sh${NC}"
   exit 1
fi

# Update system
echo -e "${CYAN}[*] Updating system packages...${NC}"
apt-get update -y
apt-get upgrade -y

# Install Python dependencies
echo -e "${CYAN}[*] Installing Python dependencies...${NC}"
apt-get install -y python3 python3-pip python3-dev
pip3 install --upgrade pip

# Install required Python packages
echo -e "${CYAN}[*] Installing Python packages...${NC}"
pip3 install requests colorama beautifulsoup4 lxml paramiko scapy

# Install hacking tools
echo -e "${CYAN}[*] Installing hacking tools...${NC}"

# Nmap
echo -e "${GREEN}[+] Installing Nmap...${NC}"
apt-get install -y nmap

# SQLMap
echo -e "${GREEN}[+] Installing SQLMap...${NC}"
apt-get install -y sqlmap

# Nikto
echo -e "${GREEN}[+] Installing Nikto...${NC}"
apt-get install -y nikto

# Gobuster
echo -e "${GREEN}[+] Installing Gobuster...${NC}"
apt-get install -y gobuster

# WPScan
echo -e "${GREEN}[+] Installing WPScan...${NC}"
apt-get install -y wpscan

# Hydra
echo -e "${GREEN}[+] Installing Hydra...${NC}"
apt-get install -y hydra

# Metasploit Framework
echo -e "${GREEN}[+] Installing Metasploit Framework...${NC}"
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
./msfinstall

# John the Ripper
echo -e "${GREEN}[+] Installing John the Ripper...${NC}"
apt-get install -y john

# Hashcat
echo -e "${GREEN}[+] Installing Hashcat...${NC}"
apt-get install -y hashcat

# Dirb
echo -e "${GREEN}[+] Installing Dirb...${NC}"
apt-get install -y dirb

# WhatWeb
echo -e "${GREEN}[+] Installing WhatWeb...${NC}"
apt-get install -y whatweb

# Sublist3r
echo -e "${GREEN}[+] Installing Sublist3r...${NC}"
apt-get install -y sublist3r

# Amass
echo -e "${GREEN}[+] Installing Amass...${NC}"
apt-get install -y amass

# Masscan
echo -e "${GREEN}[+] Installing Masscan...${NC}"
apt-get install -y masscan

# Netcat
echo -e "${GREEN}[+] Installing Netcat...${NC}"
apt-get install -y netcat

# Wget and Curl
echo -e "${GREEN}[+] Installing Wget and Curl...${NC}"
apt-get install -y wget curl

# Git
echo -e "${GREEN}[+] Installing Git...${NC}"
apt-get install -y git

# Wordlists
echo -e "${CYAN}[*] Downloading wordlists...${NC}"
mkdir -p /usr/share/wordlists
cd /usr/share/wordlists

# RockYou
if [ ! -f rockyou.txt ]; then
    echo -e "${GREEN}[+] Downloading rockyou.txt...${NC}"
    wget -q https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
fi

# SecLists
if [ ! -d SecLists ]; then
    echo -e "${GREEN}[+] Downloading SecLists...${NC}"
    git clone https://github.com/danielmiessler/SecLists.git
fi

# Common wordlists
echo -e "${GREEN}[+] Setting up common wordlists...${NC}"
ln -sf /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt /usr/share/wordlists/dirb/common.txt
ln -sf /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt /usr/share/wordlists/dirb/big.txt

# Install additional Python tools
echo -e "${CYAN}[*] Installing additional Python tools...${NC}"

# XSStrike
echo -e "${GREEN}[+] Installing XSStrike...${NC}"
git clone https://github.com/s0md3v/XSStrike.git /opt/XSStrike
cd /opt/XSStrike
pip3 install -r requirements.txt
cd -

# XXEinjector
echo -e "${GREEN}[+] Installing XXEinjector...${NC}"
git clone https://github.com/enjoiz/XXEinjector.git /opt/XXEinjector

# SSRFmap
echo -e "${GREEN}[+] Installing SSRFmap...${NC}"
git clone https://github.com/swisskyrepo/SSRFmap.git /opt/SSRFmap
cd /opt/SSRFmap
pip3 install -r requirements.txt
cd -

# NoSQLMap
echo -e "${GREEN}[+] Installing NoSQLMap...${NC}"
git clone https://github.com/codingo/NoSQLMap.git /opt/NoSQLMap
cd /opt/NoSQLMap
python3 setup.py install
cd -

# Configure WebRipper Pro
echo -e "${CYAN}[*] Configuring WebRipper Pro...${NC}"
chmod +x xpro.py

# Create symlink
ln -sf $(pwd)/xpro.py /usr/local/bin/webripper

# Create configuration directory
mkdir -p ~/.webripper
cp -r examples/ ~/.webripper/ 2>/dev/null || true

# Set up logging
mkdir -p /var/log/webripper
touch /var/log/webripper/scan.log
chmod 666 /var/log/webripper/scan.log

# Install completion
echo -e "${CYAN}[*] Setting up bash completion...${NC}"
cat > /etc/bash_completion.d/webripper << EOF
_webripper_complete() {
    local cur prev opts
    COMPREPLY=()
    cur="\${COMP_WORDS[COMP_CWORD]}"
    prev="\${COMP_WORDS[COMP_CWORD-1]}"
    opts="-t --target -s --service -m --mass --auto -h --help"
    
    if [[ \${cur} == -* ]] ; then
        COMPREPLY=( \$(compgen -W "\${opts}" -- \${cur}) )
        return 0
    fi
}
complete -F _webripper_complete webripper
complete -F _webripper_complete xpro.py
EOF

# Clean up
echo -e "${CYAN}[*] Cleaning up...${NC}"
apt-get autoremove -y
apt-get clean

# Final steps
echo -e "${CYAN}[*] Running final configuration...${NC}"

# Update Metasploit
echo -e "${GREEN}[+] Updating Metasploit database...${NC}"
msfdb init
msfdb start

# Test installations
echo -e "${CYAN}[*] Testing installations...${NC}"

tools=("nmap" "sqlmap" "nikto" "gobuster" "wpscan" "hydra" "msfconsole" "john" "hashcat")
for tool in "${tools[@]}"; do
    if command -v $tool &> /dev/null; then
        echo -e "${GREEN}[✓] $tool installed successfully${NC}"
    else
        echo -e "${RED}[✗] $tool installation failed${NC}"
    fi
done

# Display completion message
echo -e "${GREEN}"
cat << "EOF"
╔══════════════════════════════════════════════════════════╗
║                    INSTALLATION COMPLETE                 ║
╠══════════════════════════════════════════════════════════╣
║  WebRipper Pro has been successfully installed!         ║
║                                                          ║
║  Usage:                                                 ║
║    $ webripper           # Interactive mode            ║
║    $ python3 xpro.py     # Alternative                 ║
║                                                          ║
║  Quick test:                                            ║
║    $ webripper -t http://test.com -s 1                 ║
║                                                          ║
║  Remember: For educational purposes only!               ║
╚══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

echo -e "${YELLOW}[!] Please restart your terminal or run:${NC}"
echo -e "${YELLOW}[!] source ~/.bashrc${NC}"
echo -e ""
echo -e "${RED}[⚠] WARNING: Use this tool responsibly!${NC}"
echo -e "${RED}[⚠] Unauthorized hacking is illegal!${NC}"

# Create uninstall script
cat > uninstall.sh << 'EOF'
#!/bin/bash
# WebRipper Pro Uninstall Script

echo "[*] Uninstalling WebRipper Pro..."

# Remove symlink
rm -f /usr/local/bin/webripper

# Remove bash completion
rm -f /etc/bash_completion.d/webripper

# Remove configuration
rm -rf ~/.webripper
rm -rf /var/log/webripper

# Remove tools (optional - comment out if you want to keep them)
# apt-get remove -y sqlmap nikto gobuster wpscan hydra john hashcat

echo "[✓] WebRipper Pro uninstalled!"
echo "[!] Note: Hacking tools remain installed."
EOF

chmod +x uninstall.sh

echo -e "${GREEN}[+] Uninstall script created: ./uninstall.sh${NC}"
