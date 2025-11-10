module.exports = {
  testTimeout: 30000,
  verbose: true,
  setupFiles: ['./jest.setup.js'],
  preset: 'ts-jest/presets/default-esm',
  extensionsToTreatAsEsm: ['.ts', '.js'],
  globals: {
    'ts-jest': {
      useESM: true,
    },
  },
  transform: {
    '^.+\\.(ts|tsx|js|jsx|mjs)$': 'babel-jest',
  },
  moduleNameMapper: {
    '\\.(css|less|scss|sass)$': 'identity-obj-proxy',
    '^(\\.{1,2}/.*)\\.js$': '$1'
  },
  testEnvironment: "node",
  testMatch: [
    "<rootDir>/**/*.test.{ts,tsx,js,jsx,mjs}",
    "<rootDir>/test/**/*.test.{js,jsx,ts,tsx,mjs}"
  ],
  moduleFileExtensions: [
    "js",
    "jsx",
    "ts",
    "tsx",
    "mjs",
    "json",
    "node"
  ]
};
