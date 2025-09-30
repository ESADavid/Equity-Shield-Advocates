module.exports = {
  preset: 'ts-jest',
  testTimeout: 30000,
  verbose: true,
  setupFilesAfterEnv: ['./jest.setup.js'],
  transform: {
    '^.+\\.(ts|tsx|js|jsx)$': 'ts-jest',
  },
  moduleNameMapper: {
    '\\.(css|less|scss|sass)$': 'identity-obj-proxy',
  },
  globals: {
    'ts-jest': {
      tsconfig: 'tsconfig.json',
      isolatedModules: true,
      useESM: true
    },
  },
  projects: [
    {
      displayName: "backend",
      testMatch: ["<rootDir>/earnings_dashboard/**/*.test.{ts,tsx,js,jsx}", "<rootDir>/**/*.test.{ts,tsx,js,jsx}", "<rootDir>/FOUR-ERA-AI/test/**/*.ts"],
      testEnvironment: "node",
      transformIgnorePatterns: [
        "/node_modules/(?!@babel/runtime/helpers/interopRequireDefault|@babel/runtime/helpers/esm/interopRequireDefault|@babel/plugin-transform-runtime|@babel/runtime|@babel/helpers|@babel/runtime/helpers|@babel/plugin-transform-class-properties|@babel/plugin-transform-private-methods|@babel/plugin-syntax-dynamic-import|@babel/plugin-proposal-class-properties|@babel/plugin-proposal-private-methods).+\\.js$"
      ]
    },
    {
      displayName: "frontend",
      testMatch: ["<rootDir>/src/**/*.test.ts", "<rootDir>/src/**/*.test.tsx"],
      testEnvironment: "jsdom"
    }
  ]
};
