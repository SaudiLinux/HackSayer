#!/usr/bin/env python3
"""
Configuration Manager for HackSayer
Author: SayerLinux
Manages configuration settings for the penetration testing framework
"""

import json
import os
from pathlib import Path

class ConfigManager:
    """Configuration manager for HackSayer"""
    
    def __init__(self, config_dir="config"):
        self.config_dir = config_dir
        self.config_file = os.path.join(config_dir, "config.json")
        self.default_config = {
            "reconnaissance": {
                "timeout": 10,
                "max_threads": 50,
                "user_agents": [
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
                ]
            },
            "scanning": {
                "timeout": 15,
                "max_threads": 20,
                "ports": [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443],
                "vulnerability_checks": {
                    "sql_injection": True,
                    "xss": True,
                    "lfi": True,
                    "directory_traversal": True,
                    "ssl_vulnerabilities": True
                }
            },
            "exploitation": {
                "timeout": 30,
                "max_threads": 5,
                "payloads": {
                    "sql_injection": ["'", "' OR 1=1--", "' UNION SELECT NULL--"],
                    "xss": ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"],
                    "lfi": ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"]
                }
            },
            "evasion": {
                "user_agent_rotation": True,
                "delay_requests": 1,
                "randomize_headers": True,
                "proxy_usage": False
            },
            "logging": {
                "level": "INFO",
                "file_logging": True,
                "console_logging": True,
                "log_directory": "logs"
            }
        }
        self.config = self.load_config()
    
    def load_config(self):
        """Load configuration from file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                # Merge with default config
                return self.merge_configs(self.default_config, config)
            else:
                # Create default config file
                self.save_config(self.default_config)
                return self.default_config
        except Exception as e:
            print(f"Error loading config: {e}")
            return self.default_config
    
    def save_config(self, config=None):
        """Save configuration to file"""
        if config is None:
            config = self.config
        
        try:
            # Create config directory if it doesn't exist
            os.makedirs(self.config_dir, exist_ok=True)
            
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            print(f"Error saving config: {e}")
    
    def merge_configs(self, default, user):
        """Merge user config with default config"""
        merged = default.copy()
        
        for key, value in user.items():
            if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
                merged[key] = self.merge_configs(merged[key], value)
            else:
                merged[key] = value
        
        return merged
    
    def get(self, key, default=None):
        """Get configuration value"""
        keys = key.split('.')
        value = self.config
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key, value):
        """Set configuration value"""
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
        self.save_config()
    
    def get_all(self):
        """Get all configuration"""
        return self.config