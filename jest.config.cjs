module.exports = {
  testTimeout: 30000,
  verbose: true,
  setupFiles: ['./jest.setup.js'],
  preset: 'ts-jest/presets/default-esm',
  extensionsToTreatAsEsm: ['.ts'],
  globals: {
    'ts-jest': {
      useESM: true,
    },
  },
  transform: {
    '^.+\\.(ts|tsx|js|jsx)$': 'babel-jest',
  },
  transformIgnorePatterns: [
    "node_modules/(?!(@babel/runtime|jest-runner|jest-runner/build|@jest|axios|pg|bcrypt|jsonwebtoken|openai|winston|speakeasy|nodemailer|babel-jest|babel-jest/build|jest-runner/build/index.js|jest-runner/build/.*|supertest|supertest/lib|superagent|superagent/lib|methods|methods/lib|mime|mime/lib|component-emitter|component-emitter/lib|cookiejar|cookiejar/lib))/"
  ],
  moduleNameMapper: {
    '\\.(css|less|scss|sass)$': 'identity-obj-proxy',
    '^(\\.{1,2}/.*)\\.js$': '$1'
  },
  testEnvironment: "node",
  testMatch: [
    "<rootDir>/**/*.test.{ts,tsx,js,jsx}",
    "<rootDir>/test/**/*.test.{js,jsx,ts,tsx}"
  ],
  moduleFileExtensions: [
    "js",
    "jsx",
    "ts",
    "tsx",
    "json",
    "node"
  ]
};
