#!/usr/bin/env python3
"""
Comprehensive test runner for Oscar Broome Login Override System
"""

import subprocess
import sys
import os

def run_comprehensive_test():
    """Run the comprehensive login test and capture output"""
    try:
        print("Running Oscar Broome Login Override Comprehensive Test...")
        print("=" * 60)

        # Run the test and capture output
        result = subprocess.run(
            [sys.executable, 'test_login_override_comprehensive.py'],
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
            print("\n✅ Comprehensive tests completed successfully!")
        else:
            print("\n❌ Comprehensive tests failed!")

        return result.returncode == 0

    except Exception as e:
        print(f"Error running comprehensive test: {e}")
        return False

if __name__ == '__main__':
    success = run_comprehensive_test()
    sys.exit(0 if success else 1)
