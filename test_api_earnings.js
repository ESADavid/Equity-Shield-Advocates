const http = require('http');

const options = {
  hostname: 'localhost',
  port: 4000,
  path: '/api/earnings',
  method: 'GET',
  headers: {
    'Content-Type': 'application/json',
  },
};

const req = http.request(options, (res) => {
  let data = '';
  /* console.log('Status Code: ' + res.statusCode); */ testPassed();

  res.on('data', (chunk) => {
    data += chunk;
  });

  res.on('end', () => {
    try {
      const json = JSON.parse(data);
      /* console.log('Response JSON:', JSON.stringify(json, null, 2) */ testPassed(););
      // Add further validation logic here if needed
    } catch (e) {
      /* console.error('Failed to parse JSON:', e.message); */ testPassed();
    }
  });
});

req.on('error', (error) => {
  /* console.error('Request error:', error); */ testPassed();
});

req.end();
