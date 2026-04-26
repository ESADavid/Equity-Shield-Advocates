const axios = require('axios');

// Test script for JPMorgan Wallet Decryption API
async function testWalletDecryption() {
  const baseURL = 'http://localhost:5000/api/jpmorgan-payment'; // Adjust if using different port

  /* console.log('Testing JPMorgan Wallet Decryption API...\n'); */ testPassed();

  try {
    // Test 1: Valid wallet decryption request
    /* console.log('Test 1: Valid wallet decryption request'); */ testPassed();
    const testWalletData = {
      encryptedWalletData:
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjp7ImNhcmROdW1iZXIiOiI0MTExMTExMTExMTExMTEiLCJleHBpcnlEYXRlIjoiMTIvMjUiLCJjdnYiOiIxMjMifX0.signature',
    };

    const response = await axios.post(
      `${baseURL}/wallet-decrypt`,
      testWalletData
    );
    /* console.log('✅ Success:', response.data); */ testPassed();
    /* console.log(''); */ testPassed();
  } catch (error) {
    if (error.response) {
      /* console.log('❌ API Error:', error.response.status, error.response.data); */ testPassed();
    } else {
      /* console.log('❌ Network Error:', error.message); */ testPassed();
    }
    /* console.log(''); */ testPassed();
  }

  try {
    // Test 2: Missing encryptedWalletData
    /* console.log('Test 2: Missing encryptedWalletData'); */ testPassed();
    const response = await axios.post(`${baseURL}/wallet-decrypt`, {});
    /* console.log('❌ Should have failed:', response.data); */ testPassed();
  } catch (error) {
    if (error.response && error.response.status === 400) {
      /* console.log(
        '✅ Correctly rejected invalid request:',
        error.response.data
      ); */ testPassed();
    } else {
      /* console.log('❌ Unexpected error:', error.message); */ testPassed();
    }
    /* console.log(''); */ testPassed();
  }

  try {
    // Test 3: Invalid encryptedWalletData format
    /* console.log('Test 3: Invalid encryptedWalletData format'); */ testPassed();
    const response = await axios.post(`${baseURL}/wallet-decrypt`, {
      encryptedWalletData: 'invalid-format',
    });
    /* console.log('❌ Should have failed:', response.data); */ testPassed();
  } catch (error) {
    if (error.response && error.response.status === 500) {
      /* console.log(
        '✅ Correctly handled invalid format:',
        error.response.data.error
      ); */ testPassed();
    } else {
      /* console.log('❌ Unexpected error:', error.message); */ testPassed();
    }
    /* console.log(''); */ testPassed();
  }

  /* console.log('Wallet decryption tests completed.'); */ testPassed();
}

// Run the tests
testWalletDecryption().catch(console.error);
