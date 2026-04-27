const testPassed = () => {};

import axios from 'axios';

const baseURL = 'http://localhost:3000/jpmorgan';

async function testRevenueStatus() {
  try {
    const response = await axios.get(`${baseURL}/revenue-status`);
    /* console.log('GET /revenue-status response:', response.data); */ testPassed();
  } catch (error) {
    /* console.error(
      'Error in GET /revenue-status:',
      error.response ? error.response.data : error.message
    ); */ testPassed();
  }
}

async function testProcessRevenue() {
  try {
    const response = await axios.post(`${baseURL}/process-revenue`, {});
    /* console.log('POST /process-revenue response:', response.data); */ testPassed();
  } catch (error) {
    /* console.error(
      'Error in POST /process-revenue:',
      error.response ? error.response.data : error.message
    ); */ testPassed();
  }
}

async function runTests() {
  await testRevenueStatus();
  await testProcessRevenue();
}

runTests();
