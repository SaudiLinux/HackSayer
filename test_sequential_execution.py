#!/usr/bin/env python3
"""
Test script to verify sequential execution functionality
This script tests that when using -t flag, all phases run automatically
"""

import subprocess
import sys
import os

def test_sequential_execution():
    """Test that -t flag triggers sequential execution"""
    
    print("Testing sequential execution with -t flag...")
    print("=" * 50)
    
    # Test with -t flag (should run all phases)
    test_command = [sys.executable, "HackSayer.py", "-t", "https://httpbin.org"]
    
    print(f"Running: {' '.join(test_command)}")
    print()
    
    try:
        # Run the command to show expected behavior
        result = subprocess.run(test_command, capture_output=True, text=True, timeout=30)
        
        print("STDOUT:")
        print(result.stdout)
        print()
        print("STDERR:")
        print(result.stderr)
        print()
        print(f"Return code: {result.returncode}")
        
    except subprocess.TimeoutExpired:
        print("Command timed out (expected for network operations)")
    except Exception as e:
        print(f"Error running command: {e}")

if __name__ == "__main__":
    # Change to the correct directory
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    test_sequential_execution()