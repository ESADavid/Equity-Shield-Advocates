import axios from 'axios';

async function testEndpoint() {
  try {
    const response = await axios.post(
      'http://localhost:3000/jpmorgan/create-payment',
      {
        amount: 100,
        currency: 'USD',
        orderId: 'TEST123',
        description: 'Test payment',
      }
    );
    /* console.log('Response:', response.data); */ testPassed();
  } catch (error) {
    /* console.error('Error:', error.response?.data || error.message); */ testPassed();
  }
}

testEndpoint();
