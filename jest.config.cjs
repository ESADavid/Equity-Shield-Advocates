module.exports = {
  testTimeout: 30000,
  verbose: true,
  setupFiles: ['./jest.setup.js'],
  testEnvironment: 'node',
  
  // Handle ES modules properly
  extensionsToTreatAsEsm: ['.ts', '.tsx', '.mts'],
  
  // Transform configuration
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
  
  // Transform node_modules that use ES modules
  transformIgnorePatterns: [
    'node_modules/(?!(baseline-browser-mapping|@babel/runtime|jest-runner)/)',
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
