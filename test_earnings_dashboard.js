const axios = require('axios');

const BASE_URL = 'http://localhost:4000';

async function testEarningsDashboard() {
    console.log('Testing Earnings Dashboard API endpoints...\n');

    // Test 1: Dashboard page
    try {
        console.log('1. Testing dashboard page...');
        const response = await axios.get(BASE_URL);
        console.log('✓ Dashboard page loaded successfully');
        console.log('   Status:', response.status);
        console.log('   Content-Type:', response.headers['content-type']);
        console.log('   Content length:', response.data.length, 'characters\n');
    } catch (error) {
        console.log('✗ Dashboard page failed:', error.message, '\n');
    }

    // Test 2: Earnings API endpoint
    try {
        console.log('2. Testing /api/earnings endpoint...');
        const response = await axios.get(`${BASE_URL}/api/earnings`, {
            auth: {
                username: 'admin',
                password: 'securepassword'
            }
        });
        console.log('✓ Earnings API successful');
        console.log('   Status:', response.status);
        console.log('   Data type:', typeof response.data);
        if (typeof response.data === 'object') {
            console.log('   Keys:', Object.keys(response.data));
        }
        console.log('   Sample data:', JSON.stringify(response.data, null, 2).substring(0, 200) + '...\n');
    } catch (error) {
        console.log('✗ Earnings API failed:', error.response?.status, error.message);
        if (error.response?.data) {
            console.log('   Error details:', error.response.data);
        }
        console.log('');
    }

    // Test 3: Earnings download endpoint
    try {
        console.log('3. Testing /api/earnings/download endpoint...');
        const response = await axios.get(`${BASE_URL}/api/earnings/download`, {
            auth: {
                username: 'admin',
                password: 'securepassword'
            },
            responseType: 'stream'
        });
        console.log('✓ Earnings download successful');
        console.log('   Status:', response.status);
        console.log('   Content-Type:', response.headers['content-type']);
        console.log('   Content-Disposition:', response.headers['content-disposition'], '\n');
    } catch (error) {
        console.log('✗ Earnings download failed:', error.response?.status, error.message);
        if (error.response?.data) {
            console.log('   Error details:', error.response.data);
        }
        console.log('');
    }

    // Test 4: Authentication endpoint (if available)
    try {
        console.log('4. Testing /api/auth endpoint...');
        const response = await axios.get(`${BASE_URL}/api/auth`, {
            auth: {
                username: 'admin',
                password: 'securepassword'
            }
        });
        console.log('✓ Auth endpoint successful');
        console.log('   Status:', response.status);
        console.log('   Response:', response.data, '\n');
    } catch (error) {
        console.log('✗ Auth endpoint failed:', error.response?.status, error.message);
        if (error.response?.data) {
            console.log('   Error details:', error.response.data);
        }
        console.log('');
    }

    // Test 5: Invalid endpoint
    try {
        console.log('5. Testing invalid endpoint...');
        const response = await axios.get(`${BASE_URL}/api/invalid`);
        console.log('✓ Invalid endpoint handled correctly');
        console.log('   Status:', response.status);
        console.log('   Response:', response.data, '\n');
    } catch (error) {
        if (error.response?.status === 404) {
            console.log('✓ Invalid endpoint correctly returns 404');
            console.log('   Status:', error.response.status);
            console.log('   Response:', error.response.data, '\n');
        } else {
            console.log('✗ Invalid endpoint test failed:', error.message, '\n');
        }
    }

    // Test 6: Unauthorized access
    try {
        console.log('6. Testing unauthorized access...');
        const response = await axios.get(`${BASE_URL}/api/earnings`);
        console.log('✗ Unauthorized access should have failed but succeeded');
        console.log('   Status:', response.status, '\n');
    } catch (error) {
        if (error.response?.status === 401) {
            console.log('✓ Unauthorized access correctly blocked');
            console.log('   Status:', error.response.status);
            console.log('   Auth challenge:', error.response.headers['www-authenticate'], '\n');
        } else {
            console.log('✗ Unauthorized access test failed:', error.message, '\n');
        }
    }

    console.log('Testing completed.');
}

// Run the tests
testEarningsDashboard().catch(console.error);
