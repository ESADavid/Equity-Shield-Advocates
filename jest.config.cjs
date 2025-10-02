module.exports = {
  testTimeout: 30000,
  verbose: true,
  setupFilesAfterEnv: ['./jest.setup.js'],
  extensionsToTreatAsEsm: ['.ts'],
  transform: {
    '^.+\\.(ts|tsx|js|jsx)$': 'babel-jest',
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
