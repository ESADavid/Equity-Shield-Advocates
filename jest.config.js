export default {
  testEnvironment: 'node',

  // Use babel-jest for better ESM/CommonJS interoperability
  transform: {
    '^.+\\.(js|jsx|ts|tsx|mjs)$': ['babel-jest', { configFile: './babel.config.cjs' }],
  },
moduleNameMapper: {
    '^server-enhanced\\.js$': '<rootDir>/__mocks__/server-enhanced.js',
    '^server-enhanced$': '<rootDir>/__mocks__/server-enhanced.js',
    '^utils/loggerWrapper$': '<rootDir>/utils/loggerWrapper.js',
    '^utils/loggerWrapper\\.js$': '<rootDir>/utils/loggerWrapper.js',
    '^config/logger$': '<rootDir>/__mocks__/logger.js',
    '^config/logger\\.js$': '<rootDir>/__mocks__/logger.js',
    '^services/(.*)$': '<rootDir>/services/$1.js',
    '^services/(.*).js$': '<rootDir>/services/$1.js',
    '^routes/(.*)$': '<rootDir>/routes/$1.js',
    '^routes/(.*).js$': '<rootDir>/routes/$1.js',
    '^models/(.*)$': '<rootDir>/models/$1.js',
    '^models/(.*).js$': '<rootDir>/models/$1.js',
    '^public/(.*)$': '<rootDir>/public/$1',
    '^../public/(.*)$': '<rootDir>/public/$1',
    '^middleware/(.*)$': '<rootDir>/middleware/$1.js',
    '^middleware/(.*).js$': '<rootDir>/middleware/$1.js',
    '^node-cron$': '<rootDir>/__mocks__/node-cron.js',
    '^sinon$': '<rootDir>/__mocks__/sinon.js',
    '^puppeteer$': '<rootDir>/__mocks__/puppeteer.js',
    '^../owlban_revenue_repo/(.*)$': '<rootDir>/__mocks__/$1.js',
    '^../../public/js/(.*)$': '<rootDir>/__mocks__/biometric-auth.js',
    '^../models/Item\\.js$': '<rootDir>/__mocks__/Item.js',
    '\\?(.*.(png|jpg|jpeg|gif|webp))': 'identity-obj-proxy',
  },
  transformIgnorePatterns: [
    'node_modules/(?!(@testing-library|date-fns|bson|chai|uuid|mongodb|mongodb-memory-server|mongodb-memory-server-core|whatwg-url|jsdom|node-fetch)/)'
  ],
  setupFilesAfterEnv: ['<rootDir>/jest.setup.js'],
  testMatch: [
    '<rootDir>/__tests__/**/*.{js,jsx,ts,tsx}',
    '<rootDir>/src/**/__tests__/**/*.{js,jsx,ts,tsx}',
    '<rootDir>/test/**/*.{js,jsx,ts,tsx}',
    '<rootDir>/tests/**/*.{js,jsx,ts,tsx}',
    '**/*.(spec|test).{js,jsx,ts,tsx}',
  ],
  collectCoverageFrom: [
    'src/**/*.{js,jsx,ts,tsx}',
    'server-enhanced.js',
    'services/**/*.{js,jsx,ts,tsx}',
    '!**/node_modules/**',
    '!**/dist/**',
  ],
  moduleFileExtensions: ['js', 'jsx', 'ts', 'tsx', 'json', 'node', 'mjs'],
  resolver: undefined,
  verbose: true,
};
