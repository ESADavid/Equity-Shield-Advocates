#!/usr/bin/env python3
"""
Simple test runner for Oscar Broome Login Override System
"""

import subprocess
import sys
import os

def run_test():
    """Run the basic login test and capture output"""
    try:
        print("Running Oscar Broome Login Override Basic Test...")
        print("=" * 50)

        # Run the test and capture output
        result = subprocess.run(
            [sys.executable, 'test_login_basic.py'],
            capture_output=True,
            text=True,
            cwd=os.getcwd()
        )

        print("STDOUT:")
        print(result.stdout)
        print("\nSTDERR:")
        print(result.stderr)
        print("\nReturn Code:", result.returncode)

        if result.returncode == 0:
            print("\n✅ Test completed successfully!")
        else:
            print("\n❌ Test failed!")

        return result.returncode == 0

    except Exception as e:
        print(f"Error running test: {e}")
        return False

if __name__ == '__main__':
    success = run_test()
    sys.exit(0 if success else 1)
