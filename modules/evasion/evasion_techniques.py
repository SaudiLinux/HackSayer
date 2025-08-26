#!/usr/bin/env python3
"""
Evasion Techniques Module for HackSayer
Author: SayerLinux
Provides evasion techniques for bypassing security measures
"""

import random
import time
import requests
from colorama import Fore, Style

class EvasionManager:
    """Evasion techniques manager"""
    
    def __init__(self):
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0'
        ]
        
        self.accept_headers = [
            'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'application/json, text/plain, */*',
            'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        ]
    
    def apply_techniques(self):
        """Apply evasion techniques"""
        print(f"{Fore.GREEN}[EVASION] Applying evasion techniques{Style.RESET_ALL}")
        
        techniques = [
            self.rotate_user_agents,
            self.randomize_headers,
            self.add_delays,
            self.use_proxies,
            self.fragment_requests
        ]
        
        for technique in techniques:
            try:
                technique()
            except Exception as e:
                print(f"{Fore.YELLOW}[WARNING] Evasion technique failed: {e}{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}[EVASION] Evasion techniques applied{Style.RESET_ALL}")
    
    def rotate_user_agents(self):
        """Rotate user agents"""
        random_user_agent = random.choice(self.user_agents)
        return {'User-Agent': random_user_agent}
    
    def randomize_headers(self):
        """Randomize HTTP headers"""
        headers = {
            'User-Agent': random.choice(self.user_agents),
            'Accept': random.choice(self.accept_headers),
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': random.choice(['no-cache', 'max-age=0']),
            'Pragma': 'no-cache'
        }
        
        # Randomly add additional headers
        if random.choice([True, False]):
            headers['DNT'] = '1'
        
        if random.choice([True, False]):
            headers['X-Forwarded-For'] = self.generate_random_ip()
        
        return headers
    
    def add_delays(self, min_delay=1, max_delay=3):
        """Add random delays between requests"""
        delay = random.uniform(min_delay, max_delay)
        time.sleep(delay)
        return delay
    
    def use_proxies(self):
        """Use proxy rotation (placeholder)"""
        # This would implement proxy rotation
        pass
    
    def fragment_requests(self, url, data=None):
        """Fragment requests to evade detection"""
        import urllib.parse
        
        # Split URL into fragments
        parsed = urllib.parse.urlparse(url)
        fragments = []
        
        # Create fragmented request pattern
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        path_parts = parsed.path.split('/')
        
        current_path = ""
        for part in path_parts:
            if part:
                current_path += "/" + part
                fragments.append(base_url + current_path)
        
        return {
            'success': True,
            'fragments': fragments,
            'fragment_count': len(fragments),
            'technique': 'request_fragmentation',
            'timestamp': str(time.time())
        }
    
    def generate_random_ip(self):
        """Generate random IP address"""
        return f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"

    def encrypt_payload(self, payload, method='base64'):
        """Encrypt/obfuscate payload to evade detection"""
        import base64
        import urllib.parse
        
        if method == 'base64':
            encoded = base64.b64encode(payload.encode()).decode()
        elif method == 'urlencode':
            encoded = urllib.parse.quote(payload)
        elif method == 'double_urlencode':
            encoded = urllib.parse.quote(urllib.parse.quote(payload))
        elif method == 'hex':
            encoded = payload.encode().hex()
        elif method == 'unicode':
            encoded = ''.join(f'\\u{ord(c):04x}' for c in payload)
        else:
            encoded = payload
            
        return {
            'original': payload,
            'encrypted': encoded,
            'method': method,
            'length_reduction': len(payload) - len(encoded)
        }

    def obfuscate_request(self, method, url, headers=None, data=None):
        """Obfuscate HTTP request to bypass IDS/IPS"""
        import string
        
        obfuscation_techniques = []
        
        # Header obfuscation
        obfuscated_headers = headers.copy() if headers else {}
        
        # Add random benign headers
        for _ in range(random.randint(1, 3)):
            key = ''.join(random.choices(string.ascii_lowercase, k=8))
            value = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
            obfuscated_headers[key] = value
        
        # Randomize header order
        header_keys = list(obfuscated_headers.keys())
        random.shuffle(header_keys)
        obfuscated_headers = {k: obfuscated_headers[k] for k in header_keys}
        
        # Method obfuscation (case variations)
        obfuscated_method = method.upper()
        if random.choice([True, False]):
            obfuscated_method = method.lower()
        
        # URL parameter obfuscation
        obfuscated_url = url
        if '?' in url:
            base_url, params = url.split('?', 1)
            obfuscated_params = self._obfuscate_parameters(params)
            obfuscated_url = f"{base_url}?{obfuscated_params}"
        
        obfuscation_techniques.extend([
            'header_randomization',
            'parameter_obfuscation',
            'method_case_variation'
        ])
        
        return {
            'method': obfuscated_method,
            'url': obfuscated_url,
            'headers': obfuscated_headers,
            'data': data,
            'techniques': obfuscation_techniques
        }

    def _obfuscate_parameters(self, param_string):
        """Obfuscate URL parameters"""
        import urllib.parse
        
        params = urllib.parse.parse_qs(param_string)
        obfuscated_params = {}
        
        for key, values in params.items():
            # Random parameter name variations
            new_key = key
            if random.choice([True, False]):
                new_key = urllib.parse.quote(key)
            
            # Obfuscate values
            obfuscated_values = []
            for value in values:
                if random.choice([True, False]):
                    obfuscated_values.append(urllib.parse.quote(value))
                else:
                    obfuscated_values.append(value)
            
            obfuscated_params[new_key] = obfuscated_values
        
        return urllib.parse.urlencode(obfuscated_params, doseq=True)

    def create_stealth_session(self, use_tor=False, use_proxy=False):
        """Create stealth session with advanced evasion"""
        session = requests.Session()
        
        # Configure advanced evasion headers
        stealth_headers = {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'cross-site',
            'Cache-Control': 'max-age=0',
            'TE': 'Trailers'
        }
        
        # Randomize some headers
        if random.choice([True, False]):
            stealth_headers['X-Forwarded-For'] = self.generate_random_ip()
        
        session.headers.update(stealth_headers)
        
        # Configure proxy if needed
        if use_proxy:
            session.proxies = {
                'http': 'http://127.0.0.1:8080',
                'https': 'https://127.0.0.1:8080'
            }
        
        return session

    def get_evasion_headers(self):
        """Get evasion headers for requests"""
        return self.randomize_headers()

    def get_session_config(self):
        """Get session configuration with evasion"""
        return {
            'headers': self.randomize_headers(),
            'timeout': 30,
            'verify': False,  # For testing purposes only
            'allow_redirects': True
        }