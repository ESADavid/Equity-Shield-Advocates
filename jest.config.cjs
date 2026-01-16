module.exports = {
  testTimeout: 30000,
  verbose: true,
  setupFiles: ['./jest.setup.js'],
  testEnvironment: 'node',
  extensionsToTreatAsEsm: ['.ts', '.tsx'],

  // Transform configuration - transform ALL JS files including test files
  transform: {
    '^.+\\.(ts|tsx)$': [
      'babel-jest',
      {
        configFile: './babel.config.cjs',
      },
    ],
    '^.+\\.(js|jsx|mjs)$': [
      'babel-jest',
      {
        configFile: './babel.config.cjs',
      },
    ],
  },

  // Transform node_modules that use ES modules - expanded list
  transformIgnorePatterns: [
    'node_modules/(?!(baseline-browser-mapping|@babel/runtime|@noble|@paralleldrive|cuid2|formidable|superagent|supertest|chai|uuid|jsonwebtoken|bcrypt|bcryptjs|crypto-js|mathjs|merkletreejs|web3|axios|express|mongoose|mysql2|ioredis|socket.io|winston|morgan|helmet|cors|compression|express-rate-limit|express-validator|express-basic-auth|express-winston|passport|passport-jwt|twilio|nodemailer|node-cron|response-time|sha3|stripe|puppeteer|react|react-dom|d3|chart.js|recharts|lucide-react|framer-motion|react-chartjs-2|react-query|socket.io-client|pm2|baseline-browser-mapping|@headlessui|@heroicons)/)',
  ],

  // Module name mapping
  moduleNameMapper: {
    '\\.(css|less|scss|sass)$': 'identity-obj-proxy',
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },

  // File extensions Jest should look for
  moduleFileExtensions: ['js', 'jsx', 'ts', 'tsx', 'json', 'node', 'mjs'],

  // Test match patterns
  testMatch: [
    '<rootDir>/test/**/*.test.{js,jsx,ts,tsx}',
    '<rootDir>/earnings_dashboard/**/*.test.{js,jsx,ts,tsx}',
    '<rootDir>/**/*.test.{js,jsx,ts,tsx}',
  ],

  // Ignore patterns
  testPathIgnorePatterns: [
    '/node_modules/',
    '/dist/',
    '/build/',
    '/coverage/',
  ],

  // Coverage configuration
  collectCoverageFrom: [
    'services/**/*.{js,ts}',
    'routes/**/*.{js,ts}',
    'middleware/**/*.{js,ts}',
    'models/**/*.{js,ts}',
    'blockchain/**/*.{js,ts}',
    '!**/*.test.{js,ts}',
    '!**/node_modules/**',
    '!**/dist/**',
    '!**/coverage/**',
  ],
};
