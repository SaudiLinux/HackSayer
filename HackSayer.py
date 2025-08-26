#!/usr/bin/env python3
"""
HackSayer - Advanced Penetration Testing Tool
Author: SayerLinux
Website: https://github.com/SaudiLinux
Email: SayerLinux@gmail.com

A comprehensive penetration testing framework for Linux systems
featuring reconnaissance, scanning, exploitation, and post-exploitation modules
with advanced evasion techniques.
"""

import argparse
import sys
import os
import time
import json
from datetime import datetime
from colorama import Fore, Back, Style, init

# Initialize colorama for colored output
init(autoreset=True)

# Add modules to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modules'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'utils'))

# Import modules
try:
    from recon.reconnaissance import Reconnaissance
    from scanning.vulnerability_scanner import VulnerabilityScanner
    from exploitation.exploiter import Exploiter
    from post_exploitation.analyzer import PostExploitationAnalyzer
    from evasion.evasion_techniques import EvasionManager
    from utils.logger import Logger
    from utils.config_manager import ConfigManager
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Please ensure all dependencies are installed")
    sys.exit(1)

class HackSayer:
    """Main HackSayer class that orchestrates all penetration testing phases"""
    
    def __init__(self):
        self.name = "HackSayer"
        self.version = "1.0.0"
        self.author = "SayerLinux"
        self.email = "SayerLinux@gmail.com"
        self.website = "https://github.com/SaudiLinux"
        
        # Initialize components
        self.logger = Logger()
        self.config = ConfigManager()
        
        # Initialize modules
        self.recon = Reconnaissance()
        self.scanner = VulnerabilityScanner()
        self.exploiter = Exploiter()
        self.analyzer = PostExploitationAnalyzer()
        self.evasion = EvasionManager()
        
        # Results storage
        self.results = {
            'target': None,
            'recon_data': {},
            'vulnerabilities': [],
            'exploitation_results': {},
            'post_exploitation_data': {}
        }
    
    def display_banner(self):
        """Display the HackSayer banner"""
        banner = f"""
{Fore.RED}██╗  ██╗ █████╗ ██╗   ██╗ ██████╗ ███████╗██╗  ██╗ ██████╗ ███████╗
██║  ██║██╔══██╗╚██╗ ██╔╝██╔═══██╗██╔════╝██║ ██╔╝██╔═══██╗██╔════╝
███████║███████║ ╚████╔╝ ██║   ██║███████╗█████╔╝ ██║   ██║███████╗
██╔══██║██╔══██║  ╚██╔╝  ██║   ██║╚════██║██╔═██╗ ██║   ██║╚════██║
██║  ██║██║  ██║   ██║   ╚██████╔╝███████║██║  ██╗╚██████╔╝███████║
╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝
{Fore.CYAN}
╔═══════════════════════════════════════════════════════════════════════╗
║                    {Fore.YELLOW}HackSayer v{self.version}{Fore.CYAN} - Penetration Testing Framework           ║
║                    {Fore.YELLOW}Author: {self.author}{Fore.CYAN}                                     ║
║                    {Fore.YELLOW}Email: {self.email}{Fore.CYAN}                                  ║
║                    {Fore.YELLOW}Website: {self.website}{Fore.CYAN}                           ║
╚═══════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
        print(banner)
    
    def run_reconnaissance(self, target):
        """Run reconnaissance phase"""
        print(f"{Fore.GREEN}[INFO] Starting reconnaissance phase...{Style.RESET_ALL}")
        
        try:
            self.results['recon_data'] = self.recon.run(target)
            self.logger.log_info("Reconnaissance phase completed successfully")
            return True
        except Exception as e:
            self.logger.log_error(f"Reconnaissance failed: {e}")
            return False
    
    def run_vulnerability_scan(self, target):
        """Run vulnerability scanning phase"""
        print(f"{Fore.GREEN}[INFO] Starting vulnerability scanning...{Style.RESET_ALL}")
        
        try:
            self.results['vulnerabilities'] = self.scanner.scan(target)
            self.logger.log_info("Vulnerability scanning completed successfully")
            return True
        except Exception as e:
            self.logger.log_error(f"Vulnerability scanning failed: {e}")
            return False
    
    def run_exploitation(self, target):
        """Run exploitation phase"""
        print(f"{Fore.GREEN}[INFO] Starting exploitation phase...{Style.RESET_ALL}")
        
        try:
            self.results['exploitation_results'] = self.exploiter.exploit(target, self.results['vulnerabilities'])
            self.logger.log_info("Exploitation phase completed successfully")
            return True
        except Exception as e:
            self.logger.log_error(f"Exploitation failed: {e}")
            return False
    
    def run_post_exploitation(self, target):
        """Run post-exploitation analysis"""
        print(f"{Fore.GREEN}[INFO] Starting post-exploitation analysis...{Style.RESET_ALL}")
        
        try:
            self.results['post_exploitation_data'] = self.analyzer.analyze(target)
            self.logger.log_info("Post-exploitation analysis completed successfully")
            return True
        except Exception as e:
            self.logger.log_error(f"Post-exploitation analysis failed: {e}")
            return False
    
    def apply_evasion_techniques(self):
        """Apply evasion techniques"""
        print(f"{Fore.GREEN}[INFO] Applying evasion techniques...{Style.RESET_ALL}")
        
        try:
            self.evasion.apply_techniques()
            self.logger.log_info("Evasion techniques applied successfully")
            return True
        except Exception as e:
            self.logger.log_error(f"Evasion failed: {e}")
            return False
    
    def save_results(self, output_file=None):
        """Save results to file"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"hack_sayer_results_{timestamp}.json"
        
        try:
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
            
            self.logger.log_info(f"Results saved to {output_file}")
            return output_file
        except Exception as e:
            self.logger.log_error(f"Failed to save results: {e}")
            return None
    
    def generate_report(self):
        """Generate a comprehensive penetration testing report"""
        print(f"{Fore.GREEN}[INFO] Generating penetration testing report...{Style.RESET_ALL}")
        
        report = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════════════════╗
║                           {Fore.YELLOW}PENETRATION TESTING REPORT{Fore.CYAN}                      ║
╚═══════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.YELLOW}Tool Information:{Style.RESET_ALL}
- Tool: HackSayer v{self.version}
- Author: {self.author}
- Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- Target: {self.results.get('target', 'N/A')}

{Fore.YELLOW}Executive Summary:{Style.RESET_ALL}
- Reconnaissance: {'Completed' if self.results['recon_data'] else 'Not performed'}
- Vulnerabilities Found: {len(self.results['vulnerabilities'])}
- Exploitation Attempts: {'Successful' if self.results['exploitation_results'] else 'Not attempted'}
- Post-Exploitation: {'Completed' if self.results['post_exploitation_data'] else 'Not performed'}

{Fore.YELLOW}Detailed Results:{Style.RESET_ALL}
{json.dumps(self.results, indent=2, default=str)}
"""
        
        report_file = f"hack_sayer_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        try:
            with open(report_file, 'w') as f:
                f.write(report)
            
            self.logger.log_info(f"Report generated: {report_file}")
            return report_file
        except Exception as e:
            self.logger.log_error(f"Failed to generate report: {e}")
            return None

def main():
    """Main function to handle command line arguments and run HackSayer"""
    
    parser = argparse.ArgumentParser(
        description="HackSayer - Advanced Penetration Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 HackSayer.py -t 192.168.1.1 --full-scan
  python3 HackSayer.py -t example.com --recon --evasion
  python3 HackSayer.py -t 10.0.0.1 --scan --exploit
        """
    )
    
    # Required arguments
    parser.add_argument('-t', '--target', required=True, 
                       help='Target IP address or hostname')
    
    # Scanning options
    parser.add_argument('--recon', action='store_true',
                       help='Run reconnaissance phase only')
    parser.add_argument('--scan', action='store_true',
                       help='Run vulnerability scanning phase only')
    parser.add_argument('--exploit', action='store_true',
                       help='Run exploitation phase only')
    parser.add_argument('--post', action='store_true',
                       help='Run post-exploitation analysis only')
    parser.add_argument('--full-scan', action='store_true',
                       help='Run complete penetration testing workflow')
    
    # Additional options
    parser.add_argument('--evasion', action='store_true',
                       help='Apply evasion techniques')
    parser.add_argument('--output', type=str,
                       help='Output file for results')
    parser.add_argument('--config', type=str,
                       help='Custom configuration file')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Initialize HackSayer
    hacksayer = HackSayer()
    hacksayer.display_banner()
    
    # Set target
    hacksayer.results['target'] = args.target
    
    # Configure logging
    if args.verbose:
        hacksayer.logger.set_level('DEBUG')
    
    # Load custom config if provided
    if args.config:
        hacksayer.config.load_config(args.config)
    
    # Apply evasion techniques automatically for full scan or when explicitly requested
    if args.evasion or not any([args.recon, args.scan, args.exploit, args.post]):
        hacksayer.apply_evasion_techniques()
    
    # Determine which phases to run
    phases = []
    
    if args.full_scan:
        phases = ['recon', 'scan', 'exploit', 'post']
    elif args.recon:
        phases = ['recon']
    elif args.scan:
        phases = ['scan']
    elif args.exploit:
        phases = ['exploit']
    elif args.post:
        phases = ['post']
    else:
        # Default to full scan when -t is provided without specific phase flags
        phases = ['recon', 'scan', 'exploit', 'post']
    
    # Execute phases
    success = True
    
    for phase in phases:
        if phase == 'recon':
            success = hacksayer.run_reconnaissance(args.target)
        elif phase == 'scan':
            success = hacksayer.run_vulnerability_scan(args.target)
        elif phase == 'exploit':
            success = hacksayer.run_exploitation(args.target)
        elif phase == 'post':
            success = hacksayer.run_post_exploitation(args.target)
        
        if not success:
            print(f"{Fore.RED}[ERROR] Phase {phase} failed. Stopping execution.{Style.RESET_ALL}")
            break
    
    # Save results and generate report
    if success:
        print(f"{Fore.GREEN}[INFO] All phases completed successfully!{Style.RESET_ALL}")
        
        # Save results
        output_file = hacksayer.save_results(args.output)
        if output_file:
            print(f"{Fore.GREEN}[INFO] Results saved to: {output_file}{Style.RESET_ALL}")
        
        # Generate report
        report_file = hacksayer.generate_report()
        if report_file:
            print(f"{Fore.GREEN}[INFO] Report generated: {report_file}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[ERROR] Penetration testing failed.{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[INFO] Interrupted by user. Exiting...{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Unexpected error: {e}{Style.RESET_ALL}")
        sys.exit(1)