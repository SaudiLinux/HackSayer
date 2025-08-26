#!/usr/bin/env python3
"""
Logger utility for HackSayer
Author: SayerLinux
Provides logging functionality for the penetration testing framework
"""

import logging
import os
from datetime import datetime
from colorama import Fore, Style

class Logger:
    """Custom logger for HackSayer"""
    
    def __init__(self, log_dir="logs"):
        self.log_dir = log_dir
        self.setup_logging()
    
    def setup_logging(self):
        """Setup logging configuration"""
        # Create logs directory if it doesn't exist
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
        
        # Create log filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = os.path.join(self.log_dir, f"hack_sayer_{timestamp}.log")
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger('HackSayer')
        self.log_file = log_file
    
    def log_info(self, message):
        """Log info message"""
        self.logger.info(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} {message}")
    
    def log_warning(self, message):
        """Log warning message"""
        self.logger.warning(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} {message}")
    
    def log_error(self, message):
        """Log error message"""
        self.logger.error(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {message}")
    
    def log_debug(self, message):
        """Log debug message"""
        self.logger.debug(f"{Fore.CYAN}[DEBUG]{Style.RESET_ALL} {message}")
    
    def log_success(self, message):
        """Log success message"""
        self.logger.info(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {message}")
    
    def set_level(self, level):
        """Set logging level"""
        level_map = {
            'DEBUG': logging.DEBUG,
            'INFO': logging.INFO,
            'WARNING': logging.WARNING,
            'ERROR': logging.ERROR,
            'CRITICAL': logging.CRITICAL
        }
        self.logger.setLevel(level_map.get(level.upper(), logging.INFO))
    
    def get_log_file(self):
        """Get current log file path"""
        return self.log_file