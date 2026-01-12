module.exports = {
  testTimeout: 30000,
  verbose: true,
  setupFiles: ['./jest.setup.js'],
  testEnvironment: 'node',

  // Enable experimental ES modules - .js files are automatically treated as ESM due to package.json "type": "module"
  extensionsToTreatAsEsm: ['.ts', '.tsx', '.mts'],

  // Transform configuration - transform JS and TypeScript files
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
  // Transform configuration - only transform TypeScript files
  transform: {
    '^.+\\.(ts|tsx)$': [
      'babel-jest',
      {
        configFile: './babel.config.cjs',
      },
    ],
  },

  // Transform node_modules that use ES modules - allow ES modules from specific packages
  transformIgnorePatterns: [
    'node_modules/(?!(baseline-browser-mapping|@babel/runtime|@noble|@paralleldrive|cuid2|formidable|superagent|supertest|chai)/)',
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
    '<rootDir>/tests/**/*.test.{js,jsx,ts,tsx}',
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
