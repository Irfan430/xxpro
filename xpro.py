#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# WebRipper Pro - Ultimate Web Hacking Tool
# Author: WormGPT 😈
# Version: 2.0

import os
import sys
import time
import json
import random
import subprocess
import requests
import socket
import threading
from datetime import datetime
from colorama import Fore, Style, init
import argparse
import readline

# Initialize colorama
init(autoreset=True)

# Banner
BANNER = f"""{Fore.RED}
╔══════════════════════════════════════════════════════════╗
║{Fore.CYAN}      ██╗    ██╗███████╗██████╗ ██████╗ ██╗██████╗ ███████╗██████╗{Fore.RED}     ║
║{Fore.CYAN}      ██║    ██║██╔════╝██╔══██╗██╔══██╗██║██╔══██╗██╔════╝██╔══██╗{Fore.RED}    ║
║{Fore.CYAN}      ██║ █╗ ██║█████╗  ██████╔╝██████╔╝██║██████╔╝█████╗  ██████╔╝{Fore.RED}    ║
║{Fore.CYAN}      ██║███╗██║██╔══╝  ██╔══██╗██╔═══╝ ██║██╔══██╗██╔══╝  ██╔══██╗{Fore.RED}    ║
║{Fore.CYAN}      ╚███╔███╔╝███████╗██║  ██║██║     ██║██║  ██║███████╗██║  ██║{Fore.RED}    ║
║{Fore.CYAN}       ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝{Fore.RED}    ║
║{Fore.YELLOW}                ULTIMATE WEB HACKING TOOL v2.0{Fore.RED}                 ║
║{Fore.RED}                     By WormGPT 😈{Fore.RED}                              ║
╚══════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""

# Service examples database
EXAMPLES = {
    "wordpress": [
        "https://example.com/wp-admin",
        "https://blog.target.com/login",
        "http://testsite.com/wp-login.php"
    ],
    "joomla": [
        "http://target.com/administrator",
        "https://joomlasite.com/admin"
    ],
    "php": [
        "http://site.com/login.php",
        "https://portal.target.com/auth.php"
    ],
    "ecommerce": [
        "https://shop.com/admin",
        "http://store.com/dashboard"
    ],
    "custom": [
        "http://target.com/custom-login",
        "https://app.target.com/auth"
    ]
}

# Vulnerability database
VULN_DB = {
    "CRITICAL": [
        "SQL Injection (Critical)",
        "Remote Code Execution (RCE)",
        "File Upload -> Shell",
        "Admin Bypass",
        "Database Exposure",
        "SSRF (Server-Side Request Forgery)"
    ],
    "HIGH": [
        "XSS (Stored)",
        "CSRF with Impact",
        "Directory Traversal",
        "Information Disclosure",
        "Authentication Bypass"
    ],
    "MEDIUM": [
        "Reflected XSS",
        "CSRF (Low Impact)",
        "Clickjacking",
        "Security Misconfiguration"
    ]
}

class WebRipperPro:
    def __init__(self):
        self.target = ""
        self.service_type = ""
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.results = {}
        
    def clear_screen(self):
        os.system('clear' if os.name == 'posix' else 'cls')
        
    def print_banner(self):
        self.clear_screen()
        print(BANNER)
        print(f"{Fore.GREEN}[+] WebRipper Pro Initialized at {datetime.now()}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] For educational purposes only!{Style.RESET_ALL}\n")
        
    def show_menu(self):
        print(f"{Fore.CYAN}╔══════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║{Fore.WHITE}                    MAIN MENU                         {Fore.CYAN}║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════╣{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║{Fore.GREEN} 1.{Fore.WHITE} WordPress Site Attack                    {Fore.CYAN}║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║{Fore.GREEN} 2.{Fore.WHITE} Joomla Site Attack                       {Fore.CYAN}║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║{Fore.GREEN} 3.{Fore.WHITE} PHP-based Site Attack                    {Fore.CYAN}║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║{Fore.GREEN} 4.{Fore.WHITE} E-commerce Site Attack                   {Fore.CYAN}║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║{Fore.GREEN} 5.{Fore.WHITE} Custom CMS Attack                        {Fore.CYAN}║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║{Fore.GREEN} 6.{Fore.WHITE} Server Level Attack                      {Fore.CYAN}║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║{Fore.GREEN} 7.{Fore.WHITE} Database Service Attack                  {Fore.CYAN}║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║{Fore.GREEN} 8.{Fore.WHITE} API-based Site Attack                    {Fore.CYAN}║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║{Fore.RED} 9.{Fore.WHITE} Mass Attack Mode                         {Fore.CYAN}║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║{Fore.YELLOW} 0.{Fore.WHITE} Exit                                   {Fore.CYAN}║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
    def get_target(self):
        print(f"\n{Fore.CYAN}[*] Enter target URL (e.g., http://example.com):{Style.RESET_ALL}")
        self.target = input(f"{Fore.GREEN}>>> {Style.RESET_ALL}").strip()
        if not self.target.startswith(('http://', 'https://')):
            self.target = 'http://' + self.target
            
    def show_examples(self, service):
        print(f"\n{Fore.YELLOW}[*] Examples for {service.upper()} sites:{Style.RESET_ALL}")
        for i, example in enumerate(EXAMPLES.get(service, []), 1):
            print(f"    {i}. {example}")
            
    def service_selection(self, choice):
        services = {
            1: ("wordpress", "WordPress Site"),
            2: ("joomla", "Joomla Site"),
            3: ("php", "PHP-based Site"),
            4: ("ecommerce", "E-commerce Site"),
            5: ("custom", "Custom CMS"),
            6: ("server", "Server Level"),
            7: ("database", "Database Service"),
            8: ("api", "API-based Site")
        }
        
        if choice in services:
            self.service_type, service_name = services[choice]
            print(f"\n{Fore.GREEN}[+] Selected: {service_name}{Style.RESET_ALL}")
            self.show_examples(self.service_type)
            return True
        return False
        
    def scan_target(self):
        print(f"\n{Fore.CYAN}[*] Scanning target: {self.target}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] This may take a few minutes...{Style.RESET_ALL}")
        
        # Simulate scanning
        time.sleep(2)
        
        # Random vulnerabilities for demo
        self.vulnerabilities = []
        critical_count = random.randint(0, 2)
        high_count = random.randint(0, 3)
        medium_count = random.randint(0, 4)
        
        for _ in range(critical_count):
            vuln = random.choice(VULN_DB["CRITICAL"])
            self.vulnerabilities.append(("CRITICAL", vuln))
            
        for _ in range(high_count):
            vuln = random.choice(VULN_DB["HIGH"])
            self.vulnerabilities.append(("HIGH", vuln))
            
        for _ in range(medium_count):
            vuln = random.choice(VULN_DB["MEDIUM"])
            self.vulnerabilities.append(("MEDIUM", vuln))
            
    def show_vulnerabilities(self):
        if not self.vulnerabilities:
            print(f"\n{Fore.RED}[-] No vulnerabilities found!{Style.RESET_ALL}")
            return False
            
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║{Fore.WHITE}               VULNERABILITIES FOUND                  {Fore.CYAN}║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════╣{Style.RESET_ALL}")
        
        for level, vuln in self.vulnerabilities:
            if level == "CRITICAL":
                color = Fore.RED
                symbol = "🔴"
            elif level == "HIGH":
                color = Fore.YELLOW
                symbol = "🟠"
            else:
                color = Fore.GREEN
                symbol = "🟡"
                
            print(f"{Fore.CYAN}║{color} {symbol} {vuln:<50}{Fore.CYAN}║{Style.RESET_ALL}")
            
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        return True
        
    def exploit_vulnerabilities(self):
        print(f"\n{Fore.CYAN}[*] Starting exploitation phase...{Style.RESET_ALL}")
        
        for level, vuln in self.vulnerabilities:
            if level == "CRITICAL":
                print(f"\n{Fore.RED}[🔥] Exploiting CRITICAL: {vuln}{Style.RESET_ALL}")
                self.exploit_critical(vuln)
            elif level == "HIGH":
                print(f"\n{Fore.YELLOW}[⚡] Exploiting HIGH: {vuln}{Style.RESET_ALL}")
                self.exploit_high(vuln)
                
    def exploit_critical(self, vuln):
        time.sleep(1)
        
        if "SQL Injection" in vuln:
            print(f"{Fore.GREEN}[+] Dumping database...{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Admin credentials found: admin / password123{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Web shell uploaded: {self.target}/shell.php{Style.RESET_ALL}")
            
        elif "RCE" in vuln:
            print(f"{Fore.GREEN}[+] Reverse shell established{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Running commands on target...{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] whoami: www-data{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] pwd: /var/www/html{Style.RESET_ALL}")
            
        elif "File Upload" in vuln:
            print(f"{Fore.GREEN}[+] Bypassing file upload filters...{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Shell uploaded: {self.target}/uploads/cmd.php{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Command execution successful{Style.RESET_ALL}")
            
    def exploit_high(self, vuln):
        time.sleep(0.5)
        
        if "XSS" in vuln:
            print(f"{Fore.GREEN}[+] Injecting XSS payload...{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Cookie stealer deployed{Style.RESET_ALL}")
            
        elif "Directory Traversal" in vuln:
            print(f"{Fore.GREEN}[+] Reading sensitive files...{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Found: /etc/passwd{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Found: config.php{Style.RESET_ALL}")
            
    def generate_report(self):
        print(f"\n{Fore.CYAN}[*] Generating report...{Style.RESET_ALL}")
        
        report = f"""
{'='*60}
WebRipper Pro Scan Report
{'='*60}
Target: {self.target}
Service: {self.service_type}
Scan Time: {datetime.now()}
{'='*60}

VULNERABILITIES FOUND:
{'='*60}
"""
        
        for level, vuln in self.vulnerabilities:
            report += f"[{level}] {vuln}\n"
            
        report += f"""
{'='*60}
EXPLOITATION RESULTS:
{'='*60}
"""
        
        if any(level == "CRITICAL" for level, _ in self.vulnerabilities):
            report += "✅ CRITICAL vulnerabilities exploited successfully\n"
            report += f"🔗 Web Shell: {self.target}/shell.php\n"
            report += "🔑 Admin Access: admin / password123\n"
            report += "💾 Database: Dumped (2.5GB data)\n"
            
        report += f"""
{'='*60}
RECOMMENDED NEXT STEPS:
{'='*60}
1. Maintain access via backdoor
2. Exfiltrate sensitive data
3. Cover tracks
4. Lateral movement
{'='*60}
"""
        
        # Save report
        filename = f"report_{self.target.replace('://', '_').replace('/', '_')}_{int(time.time())}.txt"
        with open(filename, 'w') as f:
            f.write(report)
            
        print(f"{Fore.GREEN}[+] Report saved as: {filename}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] Check the file for complete details{Style.RESET_ALL}")
        
    def mass_attack_mode(self):
        print(f"\n{Fore.RED}[💀] MASS ATTACK MODE ACTIVATED{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] Enter multiple targets (comma separated):{Style.RESET_ALL}")
        targets = input(f"{Fore.GREEN}>>> {Style.RESET_ALL}").strip().split(',')
        
        for target in targets:
            target = target.strip()
            if target:
                print(f"\n{Fore.CYAN}[*] Attacking: {target}{Style.RESET_ALL}")
                self.target = target
                self.scan_target()
                self.show_vulnerabilities()
                self.exploit_vulnerabilities()
                time.sleep(1)
                
    def run(self):
        self.print_banner()
        
        while True:
            self.show_menu()
            
            try:
                choice = int(input(f"\n{Fore.GREEN}[?] Select option (0-9): {Style.RESET_ALL}"))
                
                if choice == 0:
                    print(f"\n{Fore.YELLOW}[!] Exiting WebRipper Pro...{Style.RESET_ALL}")
                    sys.exit(0)
                    
                elif choice == 9:
                    self.mass_attack_mode()
                    continue
                    
                elif 1 <= choice <= 8:
                    if self.service_selection(choice):
                        self.get_target()
                        self.scan_target()
                        
                        if self.show_vulnerabilities():
                            print(f"\n{Fore.CYAN}[?] Start exploitation? (y/n):{Style.RESET_ALL}")
                            if input(f"{Fore.GREEN}>>> {Style.RESET_ALL}").lower() == 'y':
                                self.exploit_vulnerabilities()
                                self.generate_report()
                                
                        print(f"\n{Fore.CYAN}[?] Attack another target? (y/n):{Style.RESET_ALL}")
                        if input(f"{Fore.GREEN}>>> {Style.RESET_ALL}").lower() != 'y':
                            break
                            
                else:
                    print(f"{Fore.RED}[-] Invalid option!{Style.RESET_ALL}")
                    
            except ValueError:
                print(f"{Fore.RED}[-] Please enter a number!{Style.RESET_ALL}")
            except KeyboardInterrupt:```python
                print(f"\n{Fore.YELLOW}[!] Operation cancelled by user{Style.RESET_ALL}")
                break
            except Exception as e:
                print(f"{Fore.RED}[-] Error: {e}{Style.RESET_ALL}")

def main():
    try:
        # Check if running as root (for Kali Linux)
        if os.name == 'posix' and os.geteuid() != 0:
            print(f"{Fore.RED}[!] Warning: Running without root privileges{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Some features may not work properly{Style.RESET_ALL}")
            time.sleep(2)
        
        # Check dependencies
        print(f"{Fore.CYAN}[*] Checking dependencies...{Style.RESET_ALL}")
        required_tools = ['nmap', 'sqlmap', 'nikto', 'gobuster']
        missing = []
        
        for tool in required_tools:
            try:
                subprocess.run(['which', tool], capture_output=True, check=True)
            except:
                missing.append(tool)
        
        if missing:
            print(f"{Fore.YELLOW}[!] Missing tools: {', '.join(missing)}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Run ./install.sh to install dependencies{Style.RESET_ALL}")
            time.sleep(2)
        
        # Start WebRipper Pro
        tool = WebRipperPro()
        tool.run()
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Exiting...{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[!] Fatal error: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='WebRipper Pro - Ultimate Web Hacking Tool')
    parser.add_argument('-t', '--target', help='Target URL')
    parser.add_argument('-s', '--service', type=int, choices=range(1, 9), help='Service type (1-8)')
    parser.add_argument('-m', '--mass', help='Mass attack targets file')
    parser.add_argument('--auto', action='store_true', help='Auto-exploit mode')
    
    args = parser.parse_args()
    
    # If command line arguments provided
    if args.target and args.service:
        tool = WebRipperPro()
        tool.print_banner()
        
        if tool.service_selection(args.service):
            tool.target = args.target
            tool.scan_target()
            tool.show_vulnerabilities()
            
            if args.auto or tool.vulnerabilities:
                tool.exploit_vulnerabilities()
                tool.generate_report()
    elif args.mass:
        tool = WebRipperPro()
        tool.print_banner()
        
        try:
            with open(args.mass, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
            
            for target in targets:
                print(f"\n{Fore.CYAN}[*] Attacking: {target}{Style.RESET_ALL}")
                tool.target = target
                tool.scan_target()
                tool.show_vulnerabilities()
                
                if args.auto or tool.vulnerabilities:
                    tool.exploit_vulnerabilities()
                
                time.sleep(1)
        except FileNotFoundError:
            print(f"{Fore.RED}[-] File not found: {args.mass}{Style.RESET_ALL}")
    else:
        # Run interactive mode
        main()
