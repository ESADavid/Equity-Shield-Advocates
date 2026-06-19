#!/usr/bin/env python3
"""
Basic test for Oscar Broome Login Override System
"""

import os
import sys

# Add the auth directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'auth'))

try:
    from login_override_fixed import authenticate_user, admin_override, verify_token

    def test_basic_functionality():
        print("Testing Oscar Broome Login Override System...")

        # Test 1: Admin login
        print("\n1. Testing admin login...")
        result = authenticate_user('admin@oscarbroomerevenue.com', 'OscarBroome2024!', '123456')
        if result['success']:
            print("✓ Admin login successful")
            token = result['tokens']['access_token']
        else:
            print("✗ Admin login failed:", result['message'])
            return False

        # Test 2: Token verification
        print("\n2. Testing token verification...")
        payload = verify_token(token)
        if payload and payload['email'] == 'admin@oscarbroomerevenue.com':
            print("✓ Token verification successful")
        else:
            print("✗ Token verification failed")
            return False

        # Test 3: Executive login
        print("\n3. Testing executive login...")
        result = authenticate_user('executive@oscarbroomerevenue.com', 'Executive2024!', '123456')
        if result['success']:
            print("✓ Executive login successful")
        else:
            print("✗ Executive login failed:", result['message'])
            return False

        # Test 4: Invalid credentials
        print("\n4. Testing invalid credentials...")
        result = authenticate_user('admin@oscarbroomerevenue.com', 'WrongPassword!')
        if not result['success'] and result['message'] == 'Invalid credentials':
            print("✓ Invalid credentials properly rejected")
        else:
            print("✗ Invalid credentials test failed")
            return False

        # Test 5: Admin override
        print("\n5. Testing admin override...")
        result = admin_override('OSCAR_BROOME_EMERGENCY_2024', 'executive@oscarbroomerevenue.com')
        if result['success']:
            print("✓ Admin override successful")
        else:
            print("✗ Admin override failed:", result['message'])
            return False

        print("\n🎉 All basic tests passed! Login override system is working correctly.")
        return True

    if __name__ == '__main__':
        success = test_basic_functionality()
        sys.exit(0 if success else 1)

except ImportError as e:
    print(f"Import error: {e}")
    print("Please ensure login_override_fixed.py is in the auth directory")
    sys.exit(1)
except Exception as e:
    print(f"Test error: {e}")
    sys.exit(1)
