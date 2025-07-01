export default {
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
      isolatedModules: true
    },
  },
  projects: [
    {
      displayName: "backend",
      testMatch: ["<rootDir>/earnings_dashboard/**/*.test.{ts,tsx,js,jsx}", "<rootDir>/**/*.test.{ts,tsx,js,jsx}", "<rootDir>/FOUR-ERA-AI/test/**/*.ts"],
      testEnvironment: "node",
      transformIgnorePatterns: [
        "/node_modules/(?!@?some-esm-module|another-esm-module|@babel/runtime/helpers/interopRequireDefault|@babel/runtime/helpers/interopRequireDefault|@babel/runtime/helpers/esm/interopRequireDefault|@babel/plugin-transform-runtime|@babel/runtime|@babel/helpers|@babel/runtime/helpers|@babel/plugin-transform-class-properties|@babel/plugin-transform-private-methods|@babel/plugin-syntax-dynamic-import).+\\.js$"
      ]
    },
    {
      displayName: "frontend",
      testMatch: ["<rootDir>/src/**/*.test.ts", "<rootDir>/src/**/*.test.tsx"],
      testEnvironment: "jsdom"
    }
  ]
};
