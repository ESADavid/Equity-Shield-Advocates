require('@testing-library/jest-dom');

global.setImmediate =
  global.setImmediate ||
  function (fn) {
    return setTimeout(fn, 0);
  };

// Polyfills for Node.js environment
const { TextEncoder, TextDecoder } = require('util');
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder;

// Set NODE_ENV to test for test environment detection
process.env.NODE_ENV = 'test';

// Set dummy environment variables for tests
process.env.DYNAMICS365_BASE_URL = 'https://dummy.dynamics365.com';
process.env.DYNAMICS365_ACCESS_TOKEN = 'dummy-token';
process.env.QUICKBOOKS_BASE_URL = 'https://dummy.quickbooks.com';
process.env.QUICKBOOKS_ACCESS_TOKEN = 'dummy-qb-token';
process.env.JPMORGAN_API_KEY = 'dummy-jp-key';
process.env.JPMORGAN_BASE_URL = 'https://dummy.jpmorgan.com';
process.env.MERCHANT_API_KEY = 'dummy-merchant-key';
process.env.TREASURY_API_KEY = 'dummy-treasury-key';
process.env.BLOCKCHAIN_NODE_URL = 'https://dummy.blockchain.com';
process.env.QUANTUM_ENCRYPTION_KEY = 'dummy-quantum-key';
