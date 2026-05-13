export default {
  // preset: 'ts-jest/presets',
  testEnvironment: 'jsdom',

  transform: {
    '^.+\\.(js|jsx|ts|tsx)$': [
      '@swc/jest',
      {
        jsc: {
          parser: {
            syntax: 'ecmascript',
            tsx: true,
            decorators: true,
            dynamicImport: true,
          },
          target: 'es2022',
          transform: {
            legacyDecorator: true,
            decoratorMetadata: true,
          },
        },
      },
    ],
},
  moduleNameMapper: {
    '^utils/loggerWrapper$': '<rootDir>/utils/loggerWrapper.js',
    '^services/(.*)$': '<rootDir>/services/$1.js',
    '^routes/(.*)$': '<rootDir>/routes/$1.js',
    '^models/(.*)$': '<rootDir>/models/$1.js',
    '^public/(.*)$': '<rootDir>/public/$1',
    '^middleware/(.*)$': '<rootDir>/middleware/$1.js',
    '\\?(.*\\.(png|jpg|jpeg|gif|webp))': 'identity-obj-proxy',
  },
  transformIgnorePatterns: ['node_modules/(?!(date-fns|@testing-library))'],
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
  moduleFileExtensions: ['js', 'jsx', 'ts', 'tsx', 'json', 'node'],
  resolver: undefined,
};
