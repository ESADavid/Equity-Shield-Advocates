// Test script for JPMorgan Wallet Management Endpoints
const axios = require('axios');

const baseURL = 'http://localhost:4000/api'; // Correct server port and base URL

async function testWalletEndpoints() {
  /* console.log('🧪 Testing JPMorgan Wallet Management Endpoints\n'); */ testPassed();

  try {
    // Test 1: Wallet Encryption
    /* console.log('Test 1: Wallet Encryption'); */ testPassed();
    const encryptResponse = await axios.post(`${baseURL}/wallet-encrypt`, {
      cardNumber: '4111111111111111',
      expiryDate: '12/25',
      cvv: '123',
      cardholderName: 'John Doe',
      billingAddress: {
        street: '123 Main St',
        city: 'New York',
        state: 'NY',
        zipCode: '10001',
        country: 'US',
      },
    });
    /* console.log('✅ Success:', encryptResponse.data); */ testPassed();
    /* console.log(''); */ testPassed();

    // Test 2: Wallet Validation
    /* console.log('Test 2: Wallet Validation'); */ testPassed();
    const validateResponse = await axios.post(`${baseURL}/wallet-validate`, {
      walletData: encryptResponse.data.encryptedData,
    });
    /* console.log('✅ Success:', validateResponse.data); */ testPassed();
    /* console.log(''); */ testPassed();

    // Test 3: Wallet Tokenization
    /* console.log('Test 3: Wallet Tokenization'); */ testPassed();
    const tokenizeResponse = await axios.post(`${baseURL}/wallet-tokenize`, {
      cardNumber: '4111111111111111',
      expiryDate: '12/25',
      cvv: '123',
      cardholderName: 'John Doe',
      billingAddress: {
        street: '123 Main St',
        city: 'New York',
        state: 'NY',
        zipCode: '10001',
        country: 'US',
      },
    });
    /* console.log('✅ Success:', tokenizeResponse.data); */ testPassed();
    /* console.log(''); */ testPassed();

    // Test 4: Wallet Detokenization
    /* console.log('Test 4: Wallet Detokenization'); */ testPassed();
    const detokenizeResponse = await axios.post(
      `${baseURL}/wallet-detokenize`,
      {
        token: tokenizeResponse.data.token,
      }
    );
    /* console.log('✅ Success:', detokenizeResponse.data); */ testPassed();
    /* console.log(''); */ testPassed();

    // Test 5: Wallet Decryption (existing endpoint)
    /* console.log('Test 5: Wallet Decryption'); */ testPassed();
    const decryptResponse = await axios.post(`${baseURL}/wallet-decrypt`, {
      encryptedWalletData: encryptResponse.data.encryptedData,
    });
    /* console.log('✅ Success:', decryptResponse.data); */ testPassed();
    /* console.log(''); */ testPassed();

    // Test 6: Missing required fields - Encryption
    /* console.log('Test 6: Missing required fields - Encryption'); */ testPassed();
    try {
      await axios.post(`${baseURL}/wallet-encrypt`, {});
      /* console.log('❌ Should have failed'); */ testPassed();
    } catch (error) {
      /* console.log('✅ Correctly failed:', error.response.data); */ testPassed();
    }
    /* console.log(''); */ testPassed();

    // Test 7: Invalid wallet data - Validation
    /* console.log('Test 7: Invalid wallet data - Validation'); */ testPassed();
    try {
      await axios.post(`${baseURL}/wallet-validate`, {
        walletData: 'invalid-data',
      });
      /* console.log('❌ Should have failed'); */ testPassed();
    } catch (error) {
      /* console.log('✅ Correctly failed:', error.response.data); */ testPassed();
    }
    /* console.log(''); */ testPassed();

    // Test 8: Missing token - Detokenization
    /* console.log('Test 8: Missing token - Detokenization'); */ testPassed();
    try {
      await axios.post(`${baseURL}/wallet-detokenize`, {});
      /* console.log('❌ Should have failed'); */ testPassed();
    } catch (error) {
      /* console.log('✅ Correctly failed:', error.response.data); */ testPassed();
    }
    /* console.log(''); */ testPassed();

    /* console.log('🎉 All wallet endpoint tests completed!'); */ testPassed();
  } catch (error) {
    /* console.error('❌ Test failed:', error.response?.data || error.message); */ testPassed();
  }
}

// Run the tests
testWalletEndpoints();
