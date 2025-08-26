#!/usr/bin/env python3
"""
Reconnaissance Module for HackSayer
Author: SayerLinux
Provides comprehensive information gathering capabilities
"""

import socket
import subprocess
import json
import requests
import dns.resolver
import whois
import shodan
import builtwith
from urllib.parse import urlparse
import concurrent.futures
import threading
import time
from colorama import Fore, Style

class Reconnaissance:
    """Reconnaissance class for gathering target information"""
    
    def __init__(self):
        self.results = {}
        self.lock = threading.Lock()
    
    def run(self, target):
        """Run complete reconnaissance on target"""
        print(f"{Fore.GREEN}[RECON] Starting comprehensive reconnaissance on {target}{Style.RESET_ALL}")
        
        self.results = {
            'target': target,
            'dns_info': {},
            'subdomains': [],
            'ports': {},
            'services': {},
            'whois_info': {},
            'tech_stack': {},
            'osint_data': {},
            'ssl_info': {},
            'directory_bruteforce': []
        }
        
        # Determine if target is IP or domain
        try:
            socket.inet_aton(target)
            is_ip = True
        except socket.error:
            is_ip = False
        
        # Run reconnaissance phases
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            
            # DNS Information
            if not is_ip:
                futures.append(executor.submit(self.get_dns_info, target))
                futures.append(executor.submit(self.find_subdomains, target))
            
            # Port scanning
            futures.append(executor.submit(self.scan_ports, target))
            
            # WHOIS information
            futures.append(executor.submit(self.get_whois_info, target))
            
            # Technology detection
            if not is_ip:
                futures.append(executor.submit(self.detect_technologies, target))
            
            # SSL/TLS information
            if not is_ip:
                futures.append(executor.submit(self.get_ssl_info, target))
            
            # Directory bruteforce
            if not is_ip:
                futures.append(executor.submit(self.bruteforce_directories, target))
            
            # Wait for all tasks to complete
            concurrent.futures.wait(futures)
        
        return self.results
    
    def get_dns_info(self, domain):
        """Get DNS information for the domain"""
        try:
            dns_info = {}
            
            # A records
            try:
                answers = dns.resolver.resolve(domain, 'A')
                dns_info['A'] = [str(answer) for answer in answers]
            except:
                dns_info['A'] = []
            
            # AAAA records
            try:
                answers = dns.resolver.resolve(domain, 'AAAA')
                dns_info['AAAA'] = [str(answer) for answer in answers]
            except:
                dns_info['AAAA'] = []
            
            # MX records
            try:
                answers = dns.resolver.resolve(domain, 'MX')
                dns_info['MX'] = [{'priority': answer.preference, 'exchange': str(answer.exchange)} for answer in answers]
            except:
                dns_info['MX'] = []
            
            # NS records
            try:
                answers = dns.resolver.resolve(domain, 'NS')
                dns_info['NS'] = [str(answer) for answer in answers]
            except:
                dns_info['NS'] = []
            
            # TXT records
            try:
                answers = dns.resolver.resolve(domain, 'TXT')
                dns_info['TXT'] = [str(answer).strip('"') for answer in answers]
            except:
                dns_info['TXT'] = []
            
            # CNAME records
            try:
                answers = dns.resolver.resolve(domain, 'CNAME')
                dns_info['CNAME'] = [str(answer) for answer in answers]
            except:
                dns_info['CNAME'] = []
            
            with self.lock:
                self.results['dns_info'] = dns_info
            
            print(f"{Fore.GREEN}[RECON] DNS information collected{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[ERROR] DNS lookup failed: {e}{Style.RESET_ALL}")
    
    def find_subdomains(self, domain):
        """Find subdomains using various techniques"""
        try:
            subdomains = set()
            
            # Common subdomains list
            common_subdomains = [
                'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api', 'blog',
                'shop', 'support', 'help', 'docs', 'cdn', 'static', 'media', 'img',
                'images', 'assets', 'js', 'css', 'fonts', 'secure', 'login', 'auth',
                'account', 'user', 'users', 'app', 'mobile', 'm', 'beta', 'old', 'new',
                'v1', 'v2', 'v3', 'api1', 'api2', 'api3', 'gateway', 'proxy', 'cache'
            ]
            
            # Check common subdomains
            for subdomain in common_subdomains:
                full_domain = f"{subdomain}.{domain}"
                try:
                    socket.gethostbyname(full_domain)
                    subdomains.add(full_domain)
                except:
                    pass
            
            # Try subdomain enumeration via crt.sh
            try:
                url = f"https://crt.sh/?q=%.{domain}&output=json"
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    for entry in data:
                        name = entry.get('name_value', '').strip()
                        if name and domain in name:
                            subdomains.add(name)
            except:
                pass
            
            with self.lock:
                self.results['subdomains'] = list(subdomains)
            
            print(f"{Fore.GREEN}[RECON] Found {len(subdomains)} subdomains{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Subdomain enumeration failed: {e}{Style.RESET_ALL}")
    
    def scan_ports(self, target):
        """Scan common ports on target"""
        try:
            common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443]
            open_ports = {}
            
            def scan_port(port):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((target, port))
                    sock.close()
                    
                    if result == 0:
                        try:
                            service = socket.getservbyport(port)
                        except:
                            service = "unknown"
                        return port, service
                except:
                    pass
                return None
            
            # Scan ports concurrently
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                futures = [executor.submit(scan_port, port) for port in common_ports]
                
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        port, service = result
                        open_ports[port] = service
            
            with self.lock:
                self.results['ports'] = open_ports
            
            print(f"{Fore.GREEN}[RECON] Scanned ports, found {len(open_ports)} open{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Port scanning failed: {e}{Style.RESET_ALL}")
    
    def get_whois_info(self, target):
        """Get WHOIS information for domain or IP"""
        try:
            # Determine if it's IP or domain
            try:
                socket.inet_aton(target)
                # It's an IP address
                whois_info = {
                    'type': 'IP',
                    'ip': target
                }
            except socket.error:
                # It's a domain
                w = whois.whois(target)
                whois_info = {
                    'type': 'domain',
                    'domain_name': w.domain_name,
                    'registrar': w.registrar,
                    'creation_date': str(w.creation_date),
                    'expiration_date': str(w.expiration_date),
                    'name_servers': w.name_servers,
                    'status': w.status,
                    'emails': w.emails,
                    'org': w.org,
                    'country': w.country
                }
            
            with self.lock:
                self.results['whois_info'] = whois_info
            
            print(f"{Fore.GREEN}[RECON] WHOIS information collected{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[ERROR] WHOIS lookup failed: {e}{Style.RESET_ALL}")
    
    def detect_technologies(self, domain):
        """Detect technologies used by the website"""
        try:
            # Ensure we have a proper URL
            if not domain.startswith(('http://', 'https://')):
                url = f"https://{domain}"
            else:
                url = domain
            
            # Use builtwith to detect technologies
            tech_info = builtwith.builtwith(url)
            
            # Additional headers analysis
            response = requests.get(url, timeout=10)
            headers = dict(response.headers)
            
            # Extract server information
            server_info = {
                'server': headers.get('Server', 'Unknown'),
                'powered_by': headers.get('X-Powered-By', 'Unknown'),
                'content_type': headers.get('Content-Type', 'Unknown'),
                'framework': 'Unknown'
            }
            
            # Detect CMS
            cms = 'Unknown'
            if 'wordpress' in str(response.text).lower():
                cms = 'WordPress'
            elif 'drupal' in str(response.text).lower():
                cms = 'Drupal'
            elif 'joomla' in str(response.text).lower():
                cms = 'Joomla'
            
            tech_data = {
                'builtwith': tech_info,
                'headers': headers,
                'server': server_info,
                'cms': cms
            }
            
            with self.lock:
                self.results['tech_stack'] = tech_data
            
            print(f"{Fore.GREEN}[RECON] Technology stack detected{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Technology detection failed: {e}{Style.RESET_ALL}")
    
    def get_ssl_info(self, domain):
        """Get SSL/TLS certificate information"""
        try:
            import ssl
            import OpenSSL
            
            # Ensure we have a proper URL
            if not domain.startswith(('http://', 'https://')):
                url = f"https://{domain}"
            else:
                url = domain
            
            hostname = urlparse(url).hostname or domain
            port = 443
            
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(True)
                    cert = ssl.DER_cert_to_PEM_cert(cert)
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
                    
                    ssl_info = {
                        'subject': dict(x509.get_subject().get_components()),
                        'issuer': dict(x509.get_issuer().get_components()),
                        'version': x509.get_version(),
                        'serial_number': str(x509.get_serial_number()),
                        'not_before': str(x509.get_notBefore()),
                        'not_after': str(x509.get_notAfter()),
                        'signature_algorithm': x509.get_signature_algorithm().decode(),
                        'public_key_length': x509.get_pubkey().bits()
                    }
                    
                    with self.lock:
                        self.results['ssl_info'] = ssl_info
                    
                    print(f"{Fore.GREEN}[RECON] SSL certificate information collected{Style.RESET_ALL}")
                    
        except Exception as e:
            print(f"{Fore.RED}[ERROR] SSL information collection failed: {e}{Style.RESET_ALL}")
    
    def bruteforce_directories(self, domain):
        """Bruteforce common directories"""
        try:
            # Ensure we have a proper URL
            if not domain.startswith(('http://', 'https://')):
                url = f"https://{domain}"
            else:
                url = domain
            
            # Common directories to check
            common_dirs = [
                'admin', 'administrator', 'api', 'backup', 'blog', 'config', 'css',
                'db', 'download', 'downloads', 'email', 'files', 'images', 'img',
                'includes', 'index', 'js', 'lib', 'login', 'logs', 'mail', 'media',
                'old', 'panel', 'phpmyadmin', 'private', 'public', 'robots.txt',
                'sitemap.xml', 'sql', 'temp', 'test', 'tmp', 'upload', 'uploads',
                'user', 'users', 'web', 'wp-admin', 'wp-content', 'wp-includes'
            ]
            
            found_dirs = []
            
            def check_directory(directory):
                try:
                    test_url = f"{url.rstrip('/')}/{directory}"
                    response = requests.get(test_url, timeout=5)
                    
                    if response.status_code == 200:
                        return {'directory': directory, 'status': response.status_code, 'url': test_url}
                    elif response.status_code in [301, 302, 307, 308]:
                        return {'directory': directory, 'status': response.status_code, 'url': test_url, 'redirect': response.headers.get('Location', '')}
                except:
                    pass
                return None
            
            # Check directories concurrently
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(check_directory, directory) for directory in common_dirs]
                
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        found_dirs.append(result)
            
            with self.lock:
                self.results['directory_bruteforce'] = found_dirs
            
            print(f"{Fore.GREEN}[RECON] Found {len(found_dirs)} accessible directories{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Directory bruteforce failed: {e}{Style.RESET_ALL}")

# Example usage
if __name__ == "__main__":
    recon = Reconnaissance()
    results = recon.run("example.com")
    print(json.dumps(results, indent=2, default=str))