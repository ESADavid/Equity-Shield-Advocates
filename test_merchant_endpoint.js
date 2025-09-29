import axios from 'axios';

async function testMerchantEndpoint() {
  try {
    console.log('Testing merchant payment intent creation...');
    const response = await axios.post('http://localhost:3000/api/merchant/create-merchant-payment-intent', {
      amount: 1000,
      currency: 'usd',
      merchantId: 'merchant_001',
      description: 'Test payment'
    });
    console.log('Response:', response.data);
  } catch (error) {
    console.error('Error:', error.response?.status, error.response?.data || error.message);
  }
}

testMerchantEndpoint();
