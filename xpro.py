#!/usr/bin/env python3
# WebRipper Pro - REAL WORKING VERSION
# Educational Purpose Only - Do NOT use illegally!

import os
import sys
import time
import requests
import socket
import subprocess
import json
from urllib.parse import urlparse, urljoin
from colorama import Fore, Style, init
import threading
from concurrent.futures import ThreadPoolExecutor
import dns.resolver
import ssl
import warnings
warnings.filterwarnings('ignore')

init(autoreset=True)

class RealHackingTool:
    def __init__(self, target):
        self.target = target
        self.parsed_url = urlparse(target)
        self.hostname = self.parsed_url.hostname
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        self.results = {
            'status': 'Not scanned',
            'server_info': {},
            'vulnerabilities': [],
            'open_ports': [],
            'directories': [],
            'subdomains': [],
            'technologies': []
        }
    
    def check_ssl(self):
        """SSL/TLS চেক"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()
                    self.results['ssl_info'] = {
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'expires': cert['notAfter'],
                        'subject': dict(x[0] for x in cert['subject'])
                    }
                    return True
        except:
            return False
    
    def get_server_info(self):
        """সার্ভার ইনফো সংগ্রহ"""
        try:
            response = self.session.get(self.target, timeout=10, verify=False)
            headers = response.headers
            
            server_info = {
                'server': headers.get('Server', 'Unknown'),
                'powered_by': headers.get('X-Powered-By', 'Unknown'),
                'content_type': headers.get('Content-Type', 'Unknown'),
                'status_code': response.status_code,
                'content_length': len(response.content)
            }
            
            # টেকনোলজি ডিটেকশন
            content = response.text.lower()
            tech_found = []
            
            tech_patterns = {
                'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
                'Joomla': ['joomla', 'joomla.org'],
                'Drupal': ['drupal', 'sites/all'],
                'Magento': ['magento', 'mage/'],
                'Laravel': ['laravel', 'csrf-token'],
                'React': ['react', 'react-dom'],
                'Vue.js': ['vue', 'vue.js'],
                'Angular': ['angular', 'ng-'],
                'jQuery': ['jquery', 'jquery.min.js'],
                'Bootstrap': ['bootstrap', 'bootstrap.min.css'],
                'Apache': ['apache', 'httpd'],
                'Nginx': ['nginx'],
                'IIS': ['microsoft-iis', 'iis'],
                'PHP': ['php', 'php/'],
                'ASP.NET': ['asp.net', 'aspx'],
                'Python': ['django', 'flask', 'python']
            }
            
            for tech, patterns in tech_patterns.items():
                for pattern in patterns:
                    if pattern.lower() in content or pattern in str(headers):
                        if tech not in tech_found:
                            tech_found.append(tech)
                            break
            
            self.results['server_info'] = server_info
            self.results['technologies'] = tech_found
            
            print(f"{Fore.GREEN}[+] Server: {server_info['server']}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Technologies: {', '.join(tech_found) if tech_found else 'Unknown'}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Status Code: {server_info['status_code']}{Style.RESET_ALL}")
            
            return True
            
        except Exception as e:
            print(f"{Fore.RED}[-] Could not get server info: {e}{Style.RESET_ALL}")
            return False
    
    def port_scan(self):
        """রিয়েল পোর্ট স্ক্যান"""
        print(f"{Fore.CYAN}[*] Scanning ports...{Style.RESET_ALL}")
        
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 
            445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443
        ]
        
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.hostname, port))
                sock.close()
                
                if result == 0:
                    service_name = socket.getservbyport(port) if port in range(1, 1024) else 'Unknown'
                    open_ports.append((port, service_name))
                    print(f"{Fore.GREEN}[+] Port {port} ({service_name}) is OPEN{Style.RESET_ALL}")
                    
            except:
                pass
        
        # Multi-threaded port scanning
        with ThreadPoolExecutor(max_workers=50) as executor:
            executor.map(scan_port, common_ports)
        
        self.results['open_ports'] = open_ports
        return open_ports
    
    def find_subdomains(self):
        """সাবডোমেইন খোঁজা"""
        print(f"{Fore.CYAN}[*] Looking for subdomains...{Style.RESET_ALL}")
        
        subdomains = []
        common_subs = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop',
            'ns1', 'ns2', 'test', 'admin', 'blog', 'dev', 'staging',
            'api', 'secure', 'vpn', 'mobile', 'shop', 'store'
        ]
        
        for sub in common_subs:
            domain = f"{sub}.{self.hostname}"
            try:
                socket.gethostbyname(domain)
                subdomains.append(domain)
                print(f"{Fore.GREEN}[+] Found subdomain: {domain}{Style.RESET_ALL}")
            except:
                pass
        
        self.results['subdomains'] = subdomains
        return subdomains
    
    def directory_enumeration(self):
        """ডিরেক্টরি এনুমারেশন"""
        print(f"{Fore.CYAN}[*] Enumerating directories...{Style.RESET_ALL}")
        
        common_dirs = [
            'admin', 'administrator', 'wp-admin', 'wp-login.php',
            'login', 'logout', 'register', 'signup', 'signin',
            'dashboard', 'controlpanel', 'cp', 'manager',
            'backup', 'backups', 'backup.zip', 'backup.sql',
            'config', 'configuration', 'config.php', 'config.inc.php',
            'db', 'database', 'sql', 'mysql', 'phpmyadmin',
            'test', 'testing', 'demo', 'example',
            'api', 'v1', 'v2', 'graphql', 'rest',
            'uploads', 'files', 'images', 'assets', 'media',
            'tmp', 'temp', 'cache', 'logs', 'error_log',
            '.git', '.svn', '.env', '.htaccess', 'robots.txt',
            'sitemap.xml', 'crossdomain.xml', 'clientaccesspolicy.xml'
        ]
        
        found_dirs = []
        
        def check_dir(directory):
            url = urljoin(self.target, directory)
            try:
                response = self.session.get(url, timeout=3, verify=False)
                
                if response.status_code == 200:
                    found_dirs.append((url, '200 OK'))
                    print(f"{Fore.GREEN}[+] Found: {url} (200){Style.RESET_ALL}")
                elif response.status_code == 403:
                    found_dirs.append((url, '403 Forbidden'))
                    print(f"{Fore.YELLOW}[!] Found (forbidden): {url}{Style.RESET_ALL}")
                elif response.status_code == 301 or response.status_code == 302:
                    found_dirs.append((url, f'{response.status_code} Redirect'))
                    print(f"{Fore.CYAN}[+] Redirect: {url} -> {response.headers.get('Location', 'Unknown')}{Style.RESET_ALL}")
                    
            except:
                pass
        
        # Multi-threaded directory checking
        with ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(check_dir, common_dirs)
        
        self.results['directories'] = found_dirs
        return found_dirs
    
    def check_vulnerabilities(self):
        """রিয়েল ভালনারবিলিটি চেক"""
        print(f"{Fore.CYAN}[*] Checking for vulnerabilities...{Style.RESET_ALL}")
        
        vulns = []
        
        # 1. Check for exposed sensitive files
        sensitive_files = [
            '.env', '.git/config', '.htaccess', 'phpinfo.php',
            'info.php', 'test.php', 'config.php', 'database.php',
            'wp-config.php', 'configuration.php', 'web.config'
        ]
        
        for file in sensitive_files:
            url = urljoin(self.target, file)
            try:
                response = self.session.get(url, timeout=3, verify=False)
                if response.status_code == 200:
                    if 'DB_PASSWORD' in response.text or 'database' in response.text.lower():
                        vulns.append(f"Exposed config file: {url}")
                        print(f"{Fore.RED}[!] CRITICAL: Exposed config file: {url}{Style.RESET_ALL}")
                    else:
                        vulns.append(f"File accessible: {url}")
                        print(f"{Fore.YELLOW}[!] File accessible: {url}{Style.RESET_ALL}")
            except:
                pass
        
        # 2. Check for SQL injection patterns
        sql_test_params = ['id', 'page', 'category', 'product', 'user']
        for param in sql_test_params:
            test_url = f"{self.target}?{param}=1'"
            try:
                response = self.session.get(test_url, timeout=3, verify=False)
                if 'sql' in response.text.lower() or 'syntax' in response.text.lower():
                    vulns.append(f"Possible SQLi in parameter: {param}")
                    print(f"{Fore.RED}[!] Possible SQL Injection in parameter: {param}{Style.RESET_ALL}")
            except:
                pass
        
        # 3. Check for XSS
        xss_payload = '<script>alert("XSS")</script>'
        test_url = f"{self.target}?q={xss_payload}"
        try:
            response = self.session.get(test_url, timeout=3, verify=False)
            if xss_payload in response.text:
                vulns.append("Reflected XSS possible")
                print(f"{Fore.YELLOW}[!] Possible Reflected XSS{Style.RESET_ALL}")
        except:
            pass
        
        # 4. Check directory listing
        dirs_to_check = ['/images/', '/uploads/', '/files/', '/assets/']
        for directory in dirs_to_check:
            url = urljoin(self.target, directory)
            try:
                response = self.session.get(url, timeout=3, verify=False)
                if 'Index of' in response.text or 'Directory listing' in response.text:
                    vulns.append(f"Directory listing enabled: {url}")
                    print(f"{Fore.YELLOW}[!] Directory listing enabled: {url}{Style.RESET_ALL}")
            except:
                pass
        
        self.results['vulnerabilities'] = vulns
        return vulns
    
    def run_external_tools(self):
        """এক্সটার্নাল টুলস রান"""
        print(f"{Fore.CYAN}[*] Running external security tools...{Style.RESET_ALL}")
        
        tools_output = {}
        
        # 1. Nmap scan (if available)
        try:
            print(f"{Fore.GREEN}[+] Running Nmap scan...{Style.RESET_ALL}")
            nmap_cmd = f"nmap -sV -sC -T4 {self.hostname}"
            result = subprocess.run(nmap_cmd, shell=True, capture_output=True, text=True, timeout=60)
            tools_output['nmap'] = result.stdout[:2000]  # Limit output
        except:
            tools_output['nmap'] = "Nmap not available or timed out"
        
        # 2. Nikto scan (if available)
        try:
            print(f"{Fore.GREEN}[+] Running Nikto scan...{Style.RESET_ALL}")
            nikto_cmd = f"nikto -h {self.target} -timeout 30"
            result = subprocess.run(nikto_cmd, shell=True, capture_output=True, text=True, timeout=90)
            tools_output['nikto'] = result.stdout[:2000]
        except:
            tools_output['nikto'] = "Nikto not available or timed out"
        
        # 3. WhatWeb scan
        try:
            print(f"{Fore.GREEN}[+] Running WhatWeb...{Style.RESET_ALL}")
            whatweb_cmd = f"whatweb {self.target} --color=never"
            result = subprocess.run(whatweb_cmd, shell=True, capture_output=True, text=True, timeout=30)
            tools_output['whatweb'] = result.stdout[:1000]
        except:
            tools_output['whatweb'] = "WhatWeb not available"
        
        self.results['tools_output'] = tools_output
        return tools_output
    
    def generate_report(self):
        """ডিটেইলড রিপোর্ট জেনারেট"""
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] GENERATING DETAILED REPORT{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        
        report = {
            'target': self.target,
            'scan_time': time.ctime(),
            'hostname': self.hostname,
            'results': self.results
        }
        
        # Display summary
        print(f"\n{Fore.YELLOW}[+] SCAN SUMMARY:{Style.RESET_ALL}")
        print(f"    Target: {self.target}")
        print(f"    Hostname: {self.hostname}")
        print(f"    Scan Time: {time.ctime()}")
        
        print(f"\n{Fore.YELLOW}[+] SERVER INFORMATION:{Style.RESET_ALL}")
        for key, value in self.results['server_info'].items():
            print(f"    {key}: {value}")
        
        print(f"\n{Fore.YELLOW}[+] TECHNOLOGIES DETECTED:{Style.RESET_ALL}")
        if self.results['technologies']:
            for tech in self.results['technologies']:
                print(f"    - {tech}")
        else:
            print("    None detected")
        
        print(f"\n{Fore.YELLOW}[+] OPEN PORTS:{Style.RESET_ALL}")
        if self.results['open_ports']:
            for port, service in self.results['open_ports']:
                print(f"    - Port {port}: {service}")
        else:
            print("    No open ports found")
        
        print(f"\n{Fore.YELLOW}[+] SUBDOMAINS FOUND:{Style.RESET_ALL}")
        if self.results['subdomains']:
            for sub in self.results['subdomains']:
                print(f"    - {sub}")
        else:
            print("    No subdomains found")
        
        print(f"\n{Fore.YELLOW}[+] DIRECTORIES FOUND:{Style.RESET_ALL}")
        if self.results['directories']:
            for url, status in self.results['directories'][:10]:  # Show first 10
                print(f"    - {url} ({status})")
            if len(self.results['directories']) > 10:
                print(f"    ... and {len(self.results['directories']) - 10} more")
        else:
            print("    No directories found")
        
        print(f"\n{Fore.YELLOW}[+] VULNERABILITIES FOUND:{Style.RESET_ALL}")
        if self.results['vulnerabilities']:
            for i, vuln in enumerate(self.results['vulnerabilities'], 1):
                print(f"    {i}. {vuln}")
        else:
            print(f"    {Fore.GREEN}No vulnerabilities found{Style.RESET_ALL}")
        
              # Save report to file
        filename = f"scan_report_{self.hostname}_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=4)
        print(f"\n{Fore.GREEN}[+] Report saved to: {filename}{Style.RESET_ALL}")      print(f"\n{Fore.GREEN}[+] Report saved to: {filename}{Style.RESET_ALL}")
        
        # Also save a text summary
        txt_filename = f"scan_summary_{self.hostname}_{int(time.time())}.txt"
        with open(txt_filename, 'w') as f:
            f.write(f"WebRipper Pro Scan Report\n")
            f.write(f"{'='*60}\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Scan Time: {time.ctime()}\n")
            f.write(f"{'='*60}\n\n")
            
            f.write("VULNERABILITIES:\n")
            f.write("-" * 40 + "\n")
            for vuln in self.results['vulnerabilities']:
                f.write(f"• {vuln}\n")
            
            f.write("\nRECOMMENDATIONS:\n")
            f.write("-" * 40 + "\n")
            if self.results['vulnerabilities']:
                f.write("1. Fix exposed configuration files\n")
                f.write("2. Implement proper input validation\n")
                f.write("3. Disable directory listing\n")
                f.write("4. Update software components\n")
                f.write("5. Implement WAF rules\n")
            else:
                f.write("No immediate security issues found.\n")
                f.write("Consider regular security audits.\n")
        
        print(f"{Fore.GREEN}[+] Text summary saved to: {txt_filename}{Style.RESET_ALL}")
        
        return filename
    
    def run_full_scan(self):
        """ফুল স্ক্যান রান"""
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] STARTING COMPREHENSIVE SECURITY SCAN{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Target: {self.target}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        
        start_time = time.time()
        
        # Step 1: Basic connectivity check
        print(f"\n{Fore.CYAN}[1/7] Checking connectivity...{Style.RESET_ALL}")
        try:
            response = requests.get(self.target, timeout=10, verify=False)
            if response.status_code != 200:
                print(f"{Fore.YELLOW}[!] Site returned status: {response.status_code}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Cannot connect to target: {e}{Style.RESET_ALL}")
            return False
        
        # Step 2: Get server info
        print(f"\n{Fore.CYAN}[2/7] Gathering server information...{Style.RESET_ALL}")
        self.get_server_info()
        
        # Step 3: Port scan
        print(f"\n{Fore.CYAN}[3/7] Scanning ports...{Style.RESET_ALL}")
        self.port_scan()
        
        # Step 4: Subdomain enumeration
        print(f"\n{Fore.CYAN}[4/7] Enumerating subdomains...{Style.RESET_ALL}")
        self.find_subdomains()
        
        # Step 5: Directory enumeration
        print(f"\n{Fore.CYAN}[5/7] Enumerating directories...{Style.RESET_ALL}")
        self.directory_enumeration()
        
        # Step 6: Vulnerability check
        print(f"\n{Fore.CYAN}[6/7] Checking for vulnerabilities...{Style.RESET_ALL}")
        self.check_vulnerabilities()
        
        # Step 7: External tools
        print(f"\n{Fore.CYAN}[7/7] Running external tools...{Style.RESET_ALL}")
        self.run_external_tools()
        
        # Generate report
        print(f"\n{Fore.CYAN}[*] Generating final report...{Style.RESET_ALL}")
        self.generate_report()
        
        elapsed_time = time.time() - start_time
        print(f"\n{Fore.GREEN}[+] Scan completed in {elapsed_time:.2f} seconds{Style.RESET_ALL}")
        
        return True

def main():
    """মেইন ফাংশন"""
    print(f"{Fore.RED}")
    print("╔══════════════════════════════════════════════════════════╗")
    print("║                 WebRipper Pro v4.0 - REAL                ║")
    print("║           Comprehensive Security Scanner                 ║")
    print("║           For Educational Purposes Only!                ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(f"{Style.RESET_ALL}")
    
    print(f"{Fore.YELLOW}[!] LEGAL DISCLAIMER:{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[!] This tool is for security testing ONLY{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[!] Use only on systems you own or have permission to test{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[!] Unauthorized access is illegal and punishable by law{Style.RESET_ALL}")
    
    consent = input(f"\n{Fore.CYAN}[?] Do you agree to use this tool legally? (y/n): {Style.RESET_ALL}")
    if consent.lower() != 'y':
        print(f"{Fore.RED}[-] Exiting...{Style.RESET_ALL}")
        sys.exit(0)
    
    target = input(f"\n{Fore.CYAN}[*] Enter target URL (e.g., http://example.com): {Style.RESET_ALL}")
    
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    
    print(f"\n{Fore.CYAN}[*] Starting scan on: {target}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] This may take 2-3 minutes...{Style.RESET_ALL}")
    
    scanner = RealHackingTool(target)
    scanner.run_full_scan()
    
    print(f"\n{Fore.GREEN}[+] Scan completed successfully!{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[!] Remember: Use findings responsibly for security improvement{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        sys.exit(1)