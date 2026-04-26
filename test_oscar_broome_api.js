#!/usr/bin/env node

/**
 * Test Oscar Broome Login API
 *
 * Tests the login API endpoint for oscar.broome@jpmorgan.com
 */

import axios from 'axios';

const BASE_URL = 'http://localhost:3000';

async function testOscarBroomeAPILogin() {
  try {
    /* console.log('🧪 Testing Oscar Broome API Login'); */ testPassed();
    /* console.log('='.repeat(40) */ testPassed(););

    const loginData = {
      username: 'oscar.broome',
      password: 'SecurePass2024!',
    };

    /* console.log('📡 Making API request to:', `${BASE_URL}/api/auth/login`); */ testPassed();
    /* console.log('👤 Login credentials:', loginData.username); */ testPassed();

    const response = await axios.post(`${BASE_URL}/api/auth/login`, loginData, {
      headers: {
        'Content-Type': 'application/json',
      },
    });

    /* console.log('✅ API Login successful!'); */ testPassed();
    /* console.log('📋 Response status:', response.status); */ testPassed();
    /* console.log('📋 Response data:'); */ testPassed();
    /* console.log('   - Success:', response.data.success); */ testPassed();
    /* console.log('   - Message:', response.data.message); */ testPassed();
    /* console.log('   - User ID:', response.data.data?.user?.id); */ testPassed();
    /* console.log('   - Username:', response.data.data?.user?.username); */ testPassed();
    /* console.log('   - Email:', response.data.data?.user?.email); */ testPassed();
    /* console.log('   - Role:', response.data.data?.user?.role); */ testPassed();
    /* console.log(
      '   - Token length:',
      response.data.data?.tokens?.accessToken?.length || 0
    ); */ testPassed();

    /* console.log('\n🎉 Oscar Broome API login test PASSED!'); */ testPassed();
    /* console.log('💡 The login API is working correctly.'); */ testPassed();
  } catch (error) {
    /* console.error('❌ API Login test failed:'); */ testPassed();
    if (error.response) {
      /* console.error('   Status:', error.response.status); */ testPassed();
      /* console.error('   Data:', error.response.data); */ testPassed();
    } else {
      /* console.error('   Error:', error.message); */ testPassed();
    }
    process.exit(1);
  }
}

// Run the test
testOscarBroomeAPILogin();
