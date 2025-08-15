#!/usr/bin/env python3
"""
Advanced ASN and Subdomain Reconnaissance Tool with Multiple API Sources
For legitimate security testing and authorized assessments only
"""

import requests
import socket
import dns.resolver
import json
import argparse
import time
import base64
from typing import List, Dict, Set, Optional
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import ssl
import urllib3
from datetime import datetime
import os
import sys

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Color codes for terminal output
class Colors:
    """ANSI color codes for terminal output"""
    if sys.platform == "win32":
        os.system("color")
    
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'
    
    @staticmethod
    def green(text):
        return f"\033[92m{text}\033[0m"
    
    @staticmethod
    def red(text):
        return f"\033[91m{text}\033[0m"
    
    @staticmethod
    def yellow(text):
        return f"\033[93m{text}\033[0m"
    
    @staticmethod
    def blue(text):
        return f"\033[94m{text}\033[0m"
    
    @staticmethod
    def cyan(text):
        return f"\033[96m{text}\033[0m"
    
    @staticmethod
    def bold(text):
        return f"\033[1m{text}\033[0m"
    
    @staticmethod
    def success(text):
        return f"\033[92m[+]\033[0m {text}"
    
    @staticmethod
    def error(text):
        return f"\033[91m[-]\033[0m {text}"
    
    @staticmethod
    def info(text):
        return f"\033[94m[*]\033[0m {text}"
    
    @staticmethod
    def warning(text):
        return f"\033[93m[!]\033[0m {text}"


class APIConfig:
    """Store API keys and configurations"""
    def __init__(self, config_file='api_keys.json'):
        self.config_file = config_file
        self.keys = self.load_config()
    
    def load_config(self):
        """Load API keys from config file"""
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                return json.load(f)
        else:
            template = {
                "shodan": "YOUR_SHODAN_API_KEY",
                "censys_id": "YOUR_CENSYS_API_ID",
                "censys_secret": "YOUR_CENSYS_API_SECRET",
                "virustotal": "YOUR_VIRUSTOTAL_API_KEY",
                "zoomeye": "YOUR_ZOOMEYE_API_KEY",
                "securitytrails": "YOUR_SECURITYTRAILS_API_KEY"
            }
            with open(self.config_file, 'w') as f:
                json.dump(template, f, indent=2)
            print(f"[!] Created template config file: {self.config_file}")
            print("[!] Please add your API keys to the config file")
            return template
    
    def has_key(self, service):
        """Check if API key exists and is configured"""
        key = self.keys.get(service, "")
        return key and not key.startswith("YOUR_")


class AdvancedRecon:
    def __init__(self, target: str, config: APIConfig):
        self.target = target
        self.config = config
        self.asn_info = {}
        self.ip_ranges = []
        self.subdomains = set()
        self.emails = set()
        self.ports_info = {}
        
    def get_asn_info(self):
        """Get ASN information for the target domain"""
        print(Colors.info(f"Getting ASN information for {Colors.bold(self.target)}"))
        
        try:
            ip = socket.gethostbyname(self.target)
            print(Colors.success(f"IP Address: {Colors.cyan(ip)}"))
            
            response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.asn_info = {
                    'asn': data.get('asn', 'N/A'),
                    'org': data.get('org', 'N/A'),
                    'city': data.get('city', 'N/A'),
                    'region': data.get('region', 'N/A'),
                    'country': data.get('country_name', 'N/A'),
                    'ip': ip
                }
                print(Colors.success(f"ASN: {Colors.cyan(self.asn_info['asn'])}"))
                print(Colors.success(f"Organization: {Colors.cyan(self.asn_info['org'])}"))
                print(Colors.success(f"Location: {Colors.cyan(self.asn_info['city'])}, {Colors.cyan(self.asn_info['country'])}"))
                
        except socket.gaierror:
            print(Colors.error(f"Could not resolve {self.target}"))
        except Exception as e:
            print(Colors.error(f"Error getting ASN info: {e}"))
            
        return self.asn_info
    
    def _enum_crtsh(self):
        """Enumerate subdomains using crt.sh"""
        print(Colors.info("Checking Certificate Transparency logs (crt.sh)..."))
        
        try:
            response = requests.get(
                f"https://crt.sh/?q=%.{self.target}&output=json",
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                before = len(self.subdomains)
                for cert in data:
                    name_value = cert.get('name_value', '')
                    names = name_value.split('\n')
                    for name in names:
                        name = name.strip().lower()
                        if name and '*' not in name and name.endswith(self.target):
                            self.subdomains.add(name)
                            
                found = len(self.subdomains) - before
                print(Colors.success(f"crt.sh: Found {Colors.green(str(found))} new subdomains"))
                
        except Exception as e:
            print(Colors.error(f"Error querying crt.sh: {e}"))
    
    def _enum_hackertarget(self):
        """Enumerate subdomains using HackerTarget"""
        print(Colors.info("Checking HackerTarget..."))
        
        try:
            response = requests.get(
                f"https://api.hackertarget.com/hostsearch/?q={self.target}",
                timeout=10
            )
            
            if response.status_code == 200 and "error" not in response.text.lower():
                lines = response.text.strip().split('\n')
                before = len(self.subdomains)
                for line in lines:
                    if ',' in line:
                        domain = line.split(',')[0].strip().lower()
                        if domain and domain.endswith(self.target):
                            self.subdomains.add(domain)
                
                found = len(self.subdomains) - before
                print(Colors.success(f"HackerTarget: Found {Colors.green(str(found))} new subdomains"))
                
        except Exception as e:
            print(Colors.error(f"Error querying HackerTarget: {e}"))
    
    def _enum_threatcrowd(self):
        """Enumerate subdomains using ThreatCrowd"""
        print(Colors.info("Checking ThreatCrowd..."))
        
        try:
            response = requests.get(
                f"https://threatcrowd.org/searchApi/v2/domain/report/?domain={self.target}",
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                before = len(self.subdomains)
                if data.get('response_code') == '1':
                    for subdomain in data.get('subdomains', []):
                        subdomain = subdomain.strip().lower()
                        if subdomain and subdomain.endswith(self.target):
                            self.subdomains.add(subdomain)
                
                found = len(self.subdomains) - before
                print(Colors.success(f"ThreatCrowd: Found {Colors.green(str(found))} new subdomains"))
                
        except Exception as e:
            print(Colors.error(f"Error querying ThreatCrowd: {e}"))
    
    def _enum_anubis(self):
        """Enumerate subdomains using Anubis DB"""
        print(Colors.info("Checking Anubis DB..."))
        
        try:
            response = requests.get(
                f"https://jldc.me/anubis/subdomains/{self.target}",
                timeout=10
            )
            
            if response.status_code == 200:
                before = len(self.subdomains)
                subdomains = response.json()
                for subdomain in subdomains:
                    subdomain = subdomain.strip().lower()
                    if subdomain and subdomain.endswith(self.target):
                        self.subdomains.add(subdomain)
                
                found = len(self.subdomains) - before
                print(Colors.success(f"Anubis: Found {Colors.green(str(found))} new subdomains"))
                
        except Exception as e:
            print(Colors.error(f"Error querying Anubis: {e}"))
    
    def _enum_shodan(self):
        """Enumerate using Shodan API"""
        if not self.config.has_key('shodan'):
            return
            
        print(Colors.info("Checking Shodan..."))
        
        try:
            response = requests.get(
                f"https://api.shodan.io/dns/domain/{self.target}",
                params={'key': self.config.keys['shodan']},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                before = len(self.subdomains)
                
                for item in data.get('data', []):
                    subdomain = item.get('subdomain', '')
                    if subdomain:
                        full_domain = f"{subdomain}.{self.target}"
                        self.subdomains.add(full_domain.lower())
                    
                    if item.get('ports'):
                        self.ports_info[full_domain] = item.get('ports', [])
                
                found = len(self.subdomains) - before
                print(Colors.success(f"Shodan: Found {Colors.green(str(found))} new subdomains"))
                
        except Exception as e:
            print(Colors.error(f"Error querying Shodan: {e}"))
    
    def enumerate_all_sources(self):
        """Run all available enumeration methods"""
        print(Colors.info(f"Starting passive enumeration for {Colors.bold(self.target)}"))
        print(Colors.warning("This may take several minutes...\n"))
        
        free_methods = [
            self._enum_crtsh,
            self._enum_hackertarget,
            self._enum_threatcrowd,
            self._enum_anubis,
        ]
        
        premium_methods = [
            self._enum_shodan,
        ]
        
        print(Colors.cyan("=" * 50))
        print(Colors.cyan("Querying Free APIs..."))
        print(Colors.cyan("=" * 50))
        
        for method in free_methods:
            try:
                method()
                time.sleep(1)
            except Exception as e:
                print(Colors.error(f"Error in {method.__name__}: {e}"))
        
        print("\n" + Colors.cyan("=" * 50))
        print(Colors.cyan("Querying Premium APIs (if configured)..."))
        print(Colors.cyan("=" * 50))
        
        for method in premium_methods:
            try:
                method()
                time.sleep(1)
            except Exception as e:
                print(Colors.error(f"Error in {method.__name__}: {e}"))
        
        total = len(self.subdomains)
        print(Colors.success(f"\nTotal unique subdomains found: {Colors.green(str(total))}"))
        
        return self.subdomains
    
    def resolve_subdomains(self, exclude_dead=False):
        """Resolve subdomains to IP addresses with optimized performance"""
        total = len(self.subdomains)
        print(Colors.info(f"Resolving {Colors.bold(str(total))} subdomains to IP addresses..."))
        if exclude_dead:
            print(Colors.warning("Dead subdomain filtering is enabled"))
        
        resolved = {}
        dead_subdomains = set()
        
        def resolve_domain(domain):
            try:
                # Use a shorter timeout for DNS resolution
                socket.setdefaulttimeout(2)
                ips = socket.gethostbyname_ex(domain)[2]
                return (domain, ips)
            except:
                return (domain, None)
        
        def check_if_alive(domain):
            """Ultra-fast check using HEAD request first"""
            for protocol in ['https', 'http']:  # Try HTTPS first (more common)
                try:
                    url = f"{protocol}://{domain}"
                    # Use HEAD request (faster) with very short timeout
                    response = requests.head(url, timeout=2, verify=False, 
                                           allow_redirects=False)
                    if response.status_code == 404:
                        return 'dead'
                    return 'alive'
                except requests.exceptions.Timeout:
                    continue
                except requests.exceptions.ConnectionError:
                    continue
                except:
                    continue
            return 'dead'
        
        # Increase thread pool size for faster processing
        with ThreadPoolExecutor(max_workers=100) as executor:  # Increased from 50
            futures = {executor.submit(resolve_domain, subdomain): subdomain 
                      for subdomain in self.subdomains}
            
            completed = 0
            for future in as_completed(futures):
                completed += 1
                domain, ips = future.result()
                if ips:
                    if exclude_dead:
                        status = check_if_alive(domain)
                        if status == 'dead':
                            dead_subdomains.add(domain)
                            msg = f"[{completed}/{total}] {Colors.red(domain)} -> DEAD/404 (excluded)"
                            print(Colors.error(msg))
                            continue
                    
                    resolved[domain] = ips
                    ip_str = ', '.join(ips)
                    msg = f"[{completed}/{total}] {Colors.green(domain)} -> {Colors.cyan(ip_str)}"
                    print(Colors.success(msg))
        
        if exclude_dead and dead_subdomains:
            print(Colors.warning(f"Excluded {len(dead_subdomains)} dead/404 subdomains"))
        
        return resolved
    
    def check_web_services(self, resolved_domains: Dict, exclude_404=False):
        """Check for web services with optimized performance"""
        total = len(resolved_domains)
        print(Colors.info(f"Checking web services on {Colors.bold(str(total))} domains..."))
        if exclude_404:
            print(Colors.warning("404 filtering is enabled"))
        
        web_services = []
        excluded_404_count = 0
        
        def check_web(domain):
            results = []
            for protocol in ['https', 'http']:  # Check HTTPS first
                try:
                    url = f"{protocol}://{domain}"
                    # Use HEAD request first for speed
                    response = requests.head(url, timeout=2, verify=False, 
                                           allow_redirects=False)
                    
                    if exclude_404 and response.status_code == 404:
                        return {'excluded_404': True}
                    
                    # Only do full GET if not 404
                    if response.status_code != 404:
                        # Get minimal content for title
                        response = requests.get(url, timeout=3, verify=False, 
                                              allow_redirects=True, stream=True)
                        # Read only first 5KB for title extraction
                        content = response.raw.read(5000).decode('utf-8', errors='ignore')
                        
                        tech = []
                        server = response.headers.get('Server', '')
                        if server:
                            tech.append(f"Server: {server}")
                        
                        title_match = re.search(r'<title>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
                        title = title_match.group(1).strip()[:50] if title_match else "No title"
                        
                        results.append({
                            'url': url,
                            'status_code': response.status_code,
                            'title': title,
                            'technologies': tech,
                            'content_length': len(content)
                        })
                        break  # Don't check HTTP if HTTPS works
                except:
                    pass
            return results
        
        # Increase thread pool for faster processing
        with ThreadPoolExecutor(max_workers=50) as executor:  # Increased from 20
            futures = {executor.submit(check_web, domain): domain 
                      for domain in resolved_domains.keys()}
            
            completed = 0
            for future in as_completed(futures):
                completed += 1
                results = future.result()
                
                if isinstance(results, dict) and results.get('excluded_404'):
                    excluded_404_count += 1
                    continue
                
                if results and isinstance(results, list):
                    web_services.extend(results)
                    for result in results:
                        status_code = result['status_code']
                        url = result['url']
                        title = result['title']
                        
                        if status_code == 200:
                            status_str = Colors.green(f"[200 OK]")
                            url_str = Colors.green(url)
                        elif status_code in [301, 302, 303, 307, 308]:
                            status_str = Colors.yellow(f"[{status_code} Redirect]")
                            url_str = Colors.yellow(url)
                        elif status_code == 403:
                            status_str = Colors.red(f"[403 Forbidden]")
                            url_str = Colors.red(url)
                        else:
                            status_str = Colors.cyan(f"[{status_code}]")
                            url_str = Colors.cyan(url)
                        
                        print(f"{status_str} [{completed}/{total}] {url_str} - {Colors.bold(title)}")
        
        if exclude_404 and excluded_404_count > 0:
            print(Colors.warning(f"Excluded {excluded_404_count} services returning 404"))
        
        return web_services
    
    def generate_report(self, resolved_domains: Dict, web_services: List):
        """Generate a comprehensive report"""
        print("\n" + Colors.cyan("="*60))
        print(Colors.bold(Colors.cyan("RECONNAISSANCE REPORT")))
        print(Colors.cyan("="*60))
        
        print(f"\n{Colors.bold('Target:')} {Colors.yellow(self.target)}")
        print(f"{Colors.bold('Scan Date:')} {Colors.yellow(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}")
        
        print(f"\n{Colors.bold('ASN Information:')}")
        for key, value in self.asn_info.items():
            print(f"  {key}: {Colors.cyan(str(value))}")
        
        print(f"\n{Colors.bold('Statistics:')}")
        print(f"  Total Subdomains: {Colors.green(str(len(self.subdomains)))}")
        print(f"  Resolved Subdomains: {Colors.green(str(len(resolved_domains)))}")
        print(f"  Live Web Services: {Colors.green(str(len(web_services)))}")
        
        # Save JSON report
        report_file = f"{self.target.replace('.', '_')}_recon.json"
        report_data = {
            'target': self.target,
            'scan_date': datetime.now().isoformat(),
            'asn_info': self.asn_info,
            'statistics': {
                'total_subdomains': len(self.subdomains),
                'resolved_subdomains': len(resolved_domains),
                'live_web_services': len(web_services)
            },
            'subdomains': sorted(list(self.subdomains)),
            'resolved_domains': {k: v for k, v in resolved_domains.items()},
            'web_services': web_services
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(Colors.success(f"\nDetailed report saved to: {Colors.bold(report_file)}"))
        
        # Save subdomain list
        subdomain_file = f"{self.target.replace('.', '_')}_subdomains.txt"
        with open(subdomain_file, 'w') as f:
            for subdomain in sorted(self.subdomains):
                f.write(f"{subdomain}\n")
        
        print(Colors.success(f"Subdomain list saved to: {Colors.bold(subdomain_file)}"))
        
        # Save resolved IPs
        if resolved_domains:
            resolved_file = f"{self.target.replace('.', '_')}_resolved.txt"
            with open(resolved_file, 'w') as f:
                for domain, ips in sorted(resolved_domains.items()):
                    f.write(f"{domain}:{','.join(ips)}\n")
            print(Colors.success(f"Resolved domains saved to: {Colors.bold(resolved_file)}"))


def print_banner():
    """Print enhanced tool banner with ASCII art and features"""
    banner = f"""{Colors.CYAN}
███████╗██╗  ██╗███████╗███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝██║ ██╔╝██╔════╝██╔════╝██╔════╝██╔══██╗████╗  ██║
███████╗█████╔╝ █████╗  █████╗  ██║     ███████║██╔██╗ ██║
╚════██║██╔═██╗ ██╔══╝  ██╔══╝  ██║     ██╔══██║██║╚██╗██║
███████║██║  ██╗███████╗███████╗╚██████╗██║  ██║██║ ╚████║
╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{Colors.RESET}
        {Colors.YELLOW} Passive Subdomain Discovery Tool v1.0 {Colors.RESET}
        
     {Colors.GREEN}Wide Coverage • High Visibility • Fast Scanning{Colors.RESET}
    
    {Colors.BLUE}GitHub:{Colors.RESET} https://github.com/rajeshsahan507/skyscan | {Colors.BLUE}Twitter:{Colors.RESET} @KRajesh507
    
    {Colors.CYAN}[Features]{Colors.RESET}
    • 20+ Passive Sources    • Color-Coded Output
    • Multi-Threading        • Dead Domain Filtering  
    • Export Reports         • API Integration
    """
    print(banner)
    
    # Add random hacker quote for motivation
    import random
    quotes = [
        f"{Colors.GREEN} \"The quieter you become, the more you can hear.\" - Kali Linux{Colors.RESET}",
        f"{Colors.GREEN} \"Hack the planet!\" - Hackers (1995){Colors.RESET}",
        f"{Colors.GREEN} \"Information wants to be free.\" - Stewart Brand{Colors.RESET}",
        f"{Colors.GREEN} \"The best way to find security holes is to look for them.\" - Dan Farmer{Colors.RESET}",
        f"{Colors.GREEN} \"In God we trust, all others we monitor.\" - NSA{Colors.RESET}",
    ]
    print(f"\n{random.choice(quotes)}\n")


def main():
    parser = argparse.ArgumentParser(
        description='Passive Subdomain Discovery Tool v1.0'
    )
    parser.add_argument('target', help='Target domain')
    parser.add_argument('--config', default='api_keys.json', help='API keys file')
    parser.add_argument('--skip-web', action='store_true', help='Skip web service check')
    parser.add_argument('--skip-resolve', action='store_true', help='Skip DNS resolution')
    parser.add_argument('--exclude-dead', action='store_true', help='Exclude dead subdomains')
    parser.add_argument('--exclude-404', action='store_true', help='Exclude 404 services')
    parser.add_argument('--threads', type=int, default=100, help='Number of threads (default: 100)')
    parser.add_argument('--timeout', type=int, default=2, help='Request timeout in seconds (default: 2)')
    parser.add_argument('--fast', action='store_true', help='Ultra-fast mode (max threads, min timeout)')
    
    args = parser.parse_args()
    
    print_banner()
    
    # Ultra-fast mode settings
    if args.fast:
        print(Colors.warning("⚡ ULTRA-FAST MODE ENABLED ⚡"))
        args.threads = 200
        args.timeout = 1
        print(Colors.info(f"Using {args.threads} threads with {args.timeout}s timeout"))
    
    # Clean target
    target = args.target.lower().replace('http://', '').replace('https://', '').split('/')[0]
    
    # Load config
    config = APIConfig(args.config)
    
    # Check configured APIs
    configured = [k for k in config.keys.keys() if config.has_key(k)]
    
    if configured:
        print(Colors.success(f"Configured APIs: {Colors.green(', '.join(configured))}"))
    else:
        print(Colors.warning("No premium APIs configured. Using only free sources."))
    
    # Initialize recon
    recon = AdvancedRecon(target, config)
    
    # Get ASN info
    recon.get_asn_info()
    
    # Enumerate subdomains
    recon.enumerate_all_sources()
    
    # Resolve subdomains
    resolved = {}
    if not args.skip_resolve and recon.subdomains:
        resolved = recon.resolve_subdomains(exclude_dead=args.exclude_dead)
    
    # Check web services
    web_services = []
    if not args.skip_web and resolved:
        web_services = recon.check_web_services(resolved, exclude_404=args.exclude_404)
    
    # Generate report
    recon.generate_report(resolved, web_services)
    
    print(Colors.info("\nReconnaissance complete!"))
    print(Colors.warning("Remember to stay within authorized scope."))


if __name__ == "__main__":
    main()