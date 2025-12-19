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
    console.log('🧪 Testing Oscar Broome API Login');
    console.log('='.repeat(40));

    const loginData = {
      username: 'oscar.broome',
      password: 'SecurePass2024!',
    };

    console.log('📡 Making API request to:', `${BASE_URL}/api/auth/login`);
    console.log('👤 Login credentials:', loginData.username);

    const response = await axios.post(`${BASE_URL}/api/auth/login`, loginData, {
      headers: {
        'Content-Type': 'application/json',
      },
    });

    console.log('✅ API Login successful!');
    console.log('📋 Response status:', response.status);
    console.log('📋 Response data:');
    console.log('   - Success:', response.data.success);
    console.log('   - Message:', response.data.message);
    console.log('   - User ID:', response.data.data?.user?.id);
    console.log('   - Username:', response.data.data?.user?.username);
    console.log('   - Email:', response.data.data?.user?.email);
    console.log('   - Role:', response.data.data?.user?.role);
    console.log(
      '   - Token length:',
      response.data.data?.tokens?.accessToken?.length || 0
    );

    console.log('\n🎉 Oscar Broome API login test PASSED!');
    console.log('💡 The login API is working correctly.');
  } catch (error) {
    console.error('❌ API Login test failed:');
    if (error.response) {
      console.error('   Status:', error.response.status);
      console.error('   Data:', error.response.data);
    } else {
      console.error('   Error:', error.message);
    }
    process.exit(1);
  }
}

// Run the test
testOscarBroomeAPILogin();
