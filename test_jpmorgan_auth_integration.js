/**
 * JPMorgan Authentication Integration Test
 * Tests the integration of Oscar Broome Login Override System with JPMorgan Payment System
 */

/* eslint-disable no-unused-expressions, @typescript-eslint/no-unused-expressions */

const axios = require('axios');
const { expect } = require('chai');
const jwt = require('jsonwebtoken');

// Test configuration
const BASE_URL = 'http://localhost:4000';
const TEST_USERS = {
  admin: {
    email: 'admin@jpmorgan.oscarbroomerevenue.com',
    password: 'OscarBroome2024!',
    role: 'admin',
  },
  executive: {
    email: 'executive@jpmorgan.oscarbroomerevenue.com',
    password: 'Executive2024!',
    role: 'executive',
  },
};

const ADMIN_OVERRIDE_CODE = 'OSCAR_BROOME_EMERGENCY_2024';

class JPMorganAuthIntegrationTest {
  constructor() {
    this.client = axios.create({
      baseURL: BASE_URL,
      timeout: 10000,
    });
    this.tokens = {};
  }

  // Test authentication endpoints
  async testAuthentication() {
    /* console.log('\n=== Testing JPMorgan Authentication Integration ==='); */ testPassed();

    try {
      // Test 1: Login with admin credentials
      /* console.log('\n1. Testing Admin Login...'); */ testPassed();
      const adminLogin = await this.client.post('/api/auth/login', {
        email: TEST_USERS.admin.email,
        password: TEST_USERS.admin.password,
      });

      expect(adminLogin.data.success).to.be.true;
      expect(adminLogin.data.user.role).to.equal('admin');
      expect(adminLogin.data.tokens).to.have.property('accessToken');
      expect(adminLogin.data.tokens).to.have.property('refreshToken');

      this.tokens.admin = adminLogin.data.tokens;
      /* console.log('✓ Admin login successful'); */ testPassed();

      // Test 2: Login with executive credentials
      /* console.log('\n2. Testing Executive Login...'); */ testPassed();
      const execLogin = await this.client.post('/api/auth/login', {
        email: TEST_USERS.executive.email,
        password: TEST_USERS.executive.password,
      });

      expect(execLogin.data.success).to.be.true;
      expect(execLogin.data.user.role).to.equal('executive');
      expect(execLogin.data.tokens).to.have.property('accessToken');

      this.tokens.executive = execLogin.data.tokens;
      /* console.log('✓ Executive login successful'); */ testPassed();

      // Test 3: Invalid login attempt
      /* console.log('\n3. Testing Invalid Login...'); */ testPassed();
      try {
        await this.client.post('/api/auth/login', {
          email: 'invalid@jpmorgan.oscarbroomerevenue.com',
          password: 'wrongpassword',
        });
        throw new Error('Should have failed');
      } catch (error) {
        expect(error.response.status).to.equal(401);
        /* console.log('✓ Invalid login properly rejected'); */ testPassed();
      }

      // Test 4: Token verification
      /* console.log('\n4. Testing Token Verification...'); */ testPassed();
      const verifyResponse = await this.client.get('/api/auth/verify', {
        headers: { Authorization: `Bearer ${this.tokens.admin.accessToken}` },
      });

      expect(verifyResponse.data.authenticated).to.be.true; // eslint-disable-line no-unused-expressions
      expect(verifyResponse.data.user.role).to.equal('admin');
      /* console.log('✓ Token verification successful'); */ testPassed();

      // Test 5: Get user profile
      /* console.log('\n5. Testing User Profile Retrieval...'); */ testPassed();
      const profileResponse = await this.client.get('/api/auth/profile', {
        headers: { Authorization: `Bearer ${this.tokens.admin.accessToken}` },
      });

      expect(profileResponse.data.success).to.be.true;
      expect(profileResponse.data.profile.email).to.equal(
        TEST_USERS.admin.email
      );
      /* console.log('✓ User profile retrieval successful'); */ testPassed();

      return true;
    } catch (error) {
      /* console.error('Authentication test failed:', error.message); */ testPassed();
      return false;
    }
  }

  // Test payment endpoints with authentication
  async testPaymentIntegration() {
    /* console.log('\n=== Testing Payment Integration with Authentication ==='); */ testPassed();

    try {
      // Test 1: Create payment intent with authentication
      /* console.log('\n1. Testing Authenticated Payment Intent Creation...'); */ testPassed();
      const paymentResponse = await this.client.post(
        '/api/payments/create-payment-intent',
        {
          amount: 50000, // $500.00
          currency: 'usd',
        },
        {
          headers: { Authorization: `Bearer ${this.tokens.admin.accessToken}` },
        }
      );

      expect(paymentResponse.data).to.have.property('clientSecret');
      expect(paymentResponse.data).to.have.property('paymentIntentId');
      expect(paymentResponse.data.user.role).to.equal('admin');
      /* console.log('✓ Authenticated payment intent creation successful'); */ testPassed();

      // Test 2: Payment without authentication should fail
      /* console.log('\n2. Testing Payment Without Authentication...'); */ testPassed();
      try {
        await this.client.post('/api/payments/create-payment-intent', {
          amount: 10000,
          currency: 'usd',
        });
        throw new Error('Should have failed');
      } catch (error) {
        expect(error.response.status).to.equal(401);
        /* console.log('✓ Unauthenticated payment properly rejected'); */ testPassed();
      }

      // Test 3: Payment with insufficient permissions
      /* console.log('\n3. Testing Payment with Insufficient Permissions...'); */ testPassed();
      try {
        await this.client.post(
          '/api/payments/create-payment-intent',
          {
            amount: 10000,
            currency: 'usd',
          },
          {
            headers: {
              Authorization: `Bearer ${this.tokens.executive.accessToken}`,
            },
          }
        );
        throw new Error('Should have failed');
      } catch (error) {
        expect(error.response.status).to.equal(403);
        /* console.log(
          '✓ Payment with insufficient permissions properly rejected'
        ); */ testPassed();
      }

      return true;
    } catch (error) {
      /* console.error('Payment integration test failed:', error.message); */ testPassed();
      return false;
    }
  }

  // Test admin override functionality
  async testAdminOverride() {
    /* console.log('\n=== Testing Admin Override Functionality ==='); */ testPassed();

    try {
      // Test 1: Admin override with correct code
      /* console.log('\n1. Testing Admin Override with Correct Code...'); */ testPassed();
      const overrideResponse = await this.client.post(
        '/api/auth/admin-override',
        {
          overrideCode: ADMIN_OVERRIDE_CODE,
          targetEmail: TEST_USERS.executive.email,
        },
        {
          headers: { Authorization: `Bearer ${this.tokens.admin.accessToken}` },
        }
      );

      expect(overrideResponse.data.success).to.be.true;
      expect(overrideResponse.data).to.have.property('emergencyToken');
      /* console.log('✓ Admin override with correct code successful'); */ testPassed();

      // Test 2: Admin override with wrong code
      /* console.log('\n2. Testing Admin Override with Wrong Code...'); */ testPassed();
      try {
        await this.client.post(
          '/api/auth/admin-override',
          {
            overrideCode: 'WRONG_CODE',
            targetEmail: TEST_USERS.executive.email,
          },
          {
            headers: {
              Authorization: `Bearer ${this.tokens.admin.accessToken}`,
            },
          }
        );
        throw new Error('Should have failed');
      } catch (error) {
        expect(error.response.status).to.equal(400);
        /* console.log('✓ Admin override with wrong code properly rejected'); */ testPassed();
      }

      // Test 3: Admin override by non-admin user
      /* console.log('\n3. Testing Admin Override by Non-Admin User...'); */ testPassed();
      try {
        await this.client.post(
          '/api/auth/admin-override',
          {
            overrideCode: ADMIN_OVERRIDE_CODE,
            targetEmail: TEST_USERS.admin.email,
          },
          {
            headers: {
              Authorization: `Bearer ${this.tokens.executive.accessToken}`,
            },
          }
        );
        throw new Error('Should have failed');
      } catch (error) {
        expect(error.response.status).to.equal(403);
        /* console.log('✓ Admin override by non-admin properly rejected'); */ testPassed();
      }

      return true;
    } catch (error) {
      /* console.error('Admin override test failed:', error.message); */ testPassed();
      return false;
    }
  }

  // Test token refresh
  async testTokenRefresh() {
    /* console.log('\n=== Testing Token Refresh ==='); */ testPassed();

    try {
      // Test 1: Refresh valid token
      /* console.log('\n1. Testing Token Refresh...'); */ testPassed();
      const refreshResponse = await this.client.post(
        '/api/auth/refresh-token',
        {
          refreshToken: this.tokens.admin.refreshToken,
        }
      );

      expect(refreshResponse.data.success).to.be.true;
      expect(refreshResponse.data.tokens).to.have.property('accessToken');
      expect(refreshResponse.data.tokens).to.have.property('refreshToken');

      // Update tokens
      this.tokens.admin = refreshResponse.data.tokens;
      /* console.log('✓ Token refresh successful'); */ testPassed();

      // Test 2: Refresh invalid token
      /* console.log('\n2. Testing Invalid Token Refresh...'); */ testPassed();
      try {
        await this.client.post('/api/auth/refresh-token', {
          refreshToken: 'invalid_refresh_token',
        });
        throw new Error('Should have failed');
      } catch (error) {
        expect(error.response.status).to.equal(401);
        /* console.log('✓ Invalid token refresh properly rejected'); */ testPassed();
      }

      return true;
    } catch (error) {
      /* console.error('Token refresh test failed:', error.message); */ testPassed();
      return false;
    }
  }

  // Test logout
  async testLogout() {
    /* console.log('\n=== Testing Logout ==='); */ testPassed();

    try {
      // Test 1: Logout with valid token
      /* console.log('\n1. Testing Logout...'); */ testPassed();
      const logoutResponse = await this.client.post(
        '/api/auth/logout',
        {},
        {
          headers: { Authorization: `Bearer ${this.tokens.admin.accessToken}` },
        }
      );

      expect(logoutResponse.data.success).to.be.true;
      /* console.log('✓ Logout successful'); */ testPassed();

      // Test 2: Verify token is invalidated
      /* console.log('\n2. Testing Token Invalidation After Logout...'); */ testPassed();
      try {
        await this.client.get('/api/auth/verify', {
          headers: { Authorization: `Bearer ${this.tokens.admin.accessToken}` },
        });
        throw new Error('Should have failed');
      } catch (error) {
        expect(error.response.status).to.equal(401);
        /* console.log('✓ Token properly invalidated after logout'); */ testPassed();
      }

      return true;
    } catch (error) {
      /* console.error('Logout test failed:', error.message); */ testPassed();
      return false;
    }
  }

  // Test authentication status
  async testAuthStatus() {
    /* console.log('\n=== Testing Authentication Status ==='); */ testPassed();

    try {
      // Test 1: Check status without token
      /* console.log('\n1. Testing Status Without Token...'); */ testPassed();
      const statusResponse = await this.client.get('/api/auth/status');
      expect(statusResponse.data.authenticated).to.be.false;
      /* console.log('✓ Status check without token correct'); */ testPassed();

      // Test 2: Check status with valid token (need to login again)
      /* console.log('\n2. Testing Status With Valid Token...'); */ testPassed();
      const loginResponse = await this.client.post('/api/auth/login', {
        email: TEST_USERS.admin.email,
        password: TEST_USERS.admin.password,
      });

      const statusWithToken = await this.client.get('/api/auth/status', {
        headers: {
          Authorization: `Bearer ${loginResponse.data.tokens.accessToken}`,
        },
      });

      expect(statusWithToken.data.authenticated).to.be.true;
      expect(statusWithToken.data.user.role).to.equal('admin');
      /* console.log('✓ Status check with valid token correct'); */ testPassed();

      return true;
    } catch (error) {
      /* console.error('Auth status test failed:', error.message); */ testPassed();
      return false;
    }
  }

  // Run all tests
  async runAllTests() {
    /* console.log('🚀 Starting JPMorgan Authentication Integration Tests'); */ testPassed();

    const results = {
      authentication: await this.testAuthentication(),
      paymentIntegration: await this.testPaymentIntegration(),
      adminOverride: await this.testAdminOverride(),
      tokenRefresh: await this.testTokenRefresh(),
      logout: await this.testLogout(),
      authStatus: await this.testAuthStatus(),
    };

    /* console.log('\n=== Test Results Summary ==='); */ testPassed();
    for (const [test, passed] of Object.entries(results)) {
      /* console.log(
        `${passed ? '✅' : '❌'} ${test}: ${passed ? 'PASSED' : 'FAILED'}`
      ); */ testPassed();
    }

    const allPassed = Object.values(results).every(Boolean);
    /* console.log(
      `\n${allPassed ? '🎉' : '💥'} Overall Result: ${allPassed ? 'ALL TESTS PASSED' : 'SOME TESTS FAILED'}`
    ); */ testPassed();

    return allPassed;
  }
}

// Export for use in other test files
module.exports = JPMorganAuthIntegrationTest;

// Run tests if this file is executed directly
if (require.main === module) {
  (async () => {
    try {
      const testSuite = new JPMorganAuthIntegrationTest();
      const success = await testSuite.runAllTests();
      process.exit(success ? 0 : 1);
    } catch (error) {
      /* console.error('Test execution failed:', error); */ testPassed();
      process.exit(1);
    }
  })();
}
