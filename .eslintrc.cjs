module.exports = {
  env: {
    browser: true,
    es2021: true,
    node: true,
    jest: true,
  },
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
  ],
  parser: '@typescript-eslint/parser',
  parserOptions: {
    ecmaVersion: 12,
    sourceType: 'module',
  },
  plugins: ['@typescript-eslint'],
  rules: {
    'no-unused-vars': ['warn', { 'argsIgnorePattern': '^_' }],
    '@typescript-eslint/no-unused-vars': 'off',
    '@typescript-eslint/no-explicit-any': 'off',
    '@typescript-eslint/no-require-imports': 'off', // Allow require() for now
    'no-undef': 'error',
    'no-case-declarations': 'off', // Allow declarations in case blocks
    'no-dupe-keys': 'error',
    'no-prototype-builtins': 'warn',
    'prefer-const': 'error',
    'no-useless-escape': 'warn',
    'no-unused-expressions': 'error',
  },
  overrides: [
    {
      files: ['*.js'],
      parser: 'espree',
      parserOptions: {
        sourceType: 'script', // Allow require() in .js files
      },
      rules: {
        '@typescript-eslint/no-unused-vars': 'off',
        'no-unused-vars': 'off',
      },
    },
    {
      files: ['tests/**/*.js'],
      parser: 'espree',
      parserOptions: {
        sourceType: 'module', // Allow import/export in test files
      },
      rules: {
        '@typescript-eslint/no-unused-vars': 'off',
        'no-unused-vars': 'off',
      },
    },
  ],
};
