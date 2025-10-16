module.exports = {
  testTimeout: 30000,
  verbose: true,
  setupFiles: ['./jest.setup.js'],
  extensionsToTreatAsEsm: ['.ts'],
  globals: {
    'ts-jest': {
      useESM: true,
    },
  },
  transform: {
    '^.+\\.(ts|tsx|js|jsx)$': ['babel-jest', { presets: ['@babel/preset-env', '@babel/preset-typescript'] }],
  },
  transformIgnorePatterns: [
    "node_modules/(?!(@babel/runtime|jest-runner))/"
  ],
  moduleNameMapper: {
    '\\.(css|less|scss|sass)$': 'identity-obj-proxy',
  },
  projects: [
    {
      displayName: "backend",
      testMatch: ["<rootDir>/earnings_dashboard/**/*.test.{ts,tsx,js,jsx}", "<rootDir>/**/*.test.{ts,tsx,js,jsx}", "<rootDir>/FOUR-ERA-AI/test/**/*.ts"],
      testEnvironment: "node"
    },
    {
      displayName: "frontend",
      testMatch: ["<rootDir>/src/**/*.test.ts", "<rootDir>/src/**/*.test.tsx"],
      testEnvironment: "jsdom"
    }
  ]
};
