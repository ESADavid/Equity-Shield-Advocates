module.exports = {
  preset: 'ts-jest',
  testTimeout: 30000,
  verbose: true,
  setupFilesAfterEnv: ['./jest.setup.js'],
  transform: {
    '^.+\\.(ts|tsx)$': 'ts-jest',
    '^.+\\.(js|jsx)$': 'babel-jest',
  },
  moduleNameMapper: {
    '\\.(css|less|scss|sass)$': 'identity-obj-proxy',
  },
  globals: {
    'ts-jest': {
      tsconfig: 'tsconfig.json',
    },
  },
  projects: [
    {
      displayName: "backend",
      testMatch: ["<rootDir>/earnings_dashboard/server.test.js", "<rootDir>/earnings_dashboard/server.test.ts", "<rootDir>/earnings_dashboard/api.test.js", "<rootDir>/earnings_dashboard/payroll_integration.test.ts", "<rootDir>/earnings_dashboard/payroll_integration.test.js"],
      testEnvironment: "node"
    },
    {
      displayName: "frontend",
      testMatch: ["<rootDir>/src/**/*.test.ts", "<rootDir>/src/**/*.test.tsx"],
      testEnvironment: "jsdom"
    }
  ]
};
