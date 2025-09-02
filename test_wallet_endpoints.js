// Test script for JPMorgan Wallet Management Endpoints
const axios = require('axios');

const baseURL = 'http://localhost:4000/api'; // Correct server port and base URL

async function testWalletEndpoints() {
  console.log('🧪 Testing JPMorgan Wallet Management Endpoints\n');

  try {
    // Test 1: Wallet Encryption
    console.log('Test 1: Wallet Encryption');
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
        country: 'US'
      }
    });
    console.log('✅ Success:', encryptResponse.data);
    console.log('');

    // Test 2: Wallet Validation
    console.log('Test 2: Wallet Validation');
    const validateResponse = await axios.post(`${baseURL}/wallet-validate`, {
      walletData: encryptResponse.data.encryptedData
    });
    console.log('✅ Success:', validateResponse.data);
    console.log('');

    // Test 3: Wallet Tokenization
    console.log('Test 3: Wallet Tokenization');
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
        country: 'US'
      }
    });
    console.log('✅ Success:', tokenizeResponse.data);
    console.log('');

    // Test 4: Wallet Detokenization
    console.log('Test 4: Wallet Detokenization');
    const detokenizeResponse = await axios.post(`${baseURL}/wallet-detokenize`, {
      token: tokenizeResponse.data.token
    });
    console.log('✅ Success:', detokenizeResponse.data);
    console.log('');

    // Test 5: Wallet Decryption (existing endpoint)
    console.log('Test 5: Wallet Decryption');
    const decryptResponse = await axios.post(`${baseURL}/wallet-decrypt`, {
      encryptedWalletData: encryptResponse.data.encryptedData
    });
    console.log('✅ Success:', decryptResponse.data);
    console.log('');

    // Test 6: Missing required fields - Encryption
    console.log('Test 6: Missing required fields - Encryption');
    try {
      await axios.post(`${baseURL}/wallet-encrypt`, {});
      console.log('❌ Should have failed');
    } catch (error) {
      console.log('✅ Correctly failed:', error.response.data);
    }
    console.log('');

    // Test 7: Invalid wallet data - Validation
    console.log('Test 7: Invalid wallet data - Validation');
    try {
      await axios.post(`${baseURL}/wallet-validate`, {
        walletData: 'invalid-data'
      });
      console.log('❌ Should have failed');
    } catch (error) {
      console.log('✅ Correctly failed:', error.response.data);
    }
    console.log('');

    // Test 8: Missing token - Detokenization
    console.log('Test 8: Missing token - Detokenization');
    try {
      await axios.post(`${baseURL}/wallet-detokenize`, {});
      console.log('❌ Should have failed');
    } catch (error) {
      console.log('✅ Correctly failed:', error.response.data);
    }
    console.log('');

    console.log('🎉 All wallet endpoint tests completed!');

  } catch (error) {
    console.error('❌ Test failed:', error.response?.data || error.message);
  }
}

// Run the tests
testWalletEndpoints();
