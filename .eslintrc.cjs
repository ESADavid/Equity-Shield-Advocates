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
      files: ['tests/**/*.js', 'test/**/*.js', 'test/**/*.mjs', 'test/**/*.cjs'],
      parser: 'espree',
      parserOptions: {
        sourceType: 'module', // Allow import/export in test files
      },
      rules: {
        '@typescript-eslint/no-unused-vars': 'off',
        'no-unused-vars': 'off',
      },
    },
    {
      files: ['earnings_dashboard/**/*.js', 'quantum/**/*.js', 'auth/**/*.js', 'blockchain/**/*.js', 'comprehensive_*.js', 'cypress/**/*.js', 'ecosystem.config.js', 'executive-portal/**/*.js', 'middleware/**/*.js', 'models/**/*.js', 'routes/**/*.js', 'scripts/**/*.js', 'services/**/*.js', 'staging_*.js', 'test_*.js', 'vite.config.js', 'config/**/*.js', 'frontend/**/*.js', 'blackbox_integration/**/*.js', 'ai_models/**/*.js', 'public/**/*.js', 'monitoring/**/*.js', 'test/**/*.js', 'owlban_revenue_repo/**/*.js'],
      parser: 'espree',
      parserOptions: {
        sourceType: 'module', // Allow import/export in various module files
        ecmaVersion: 2020,
      },
      rules: {
        '@typescript-eslint/no-unused-vars': 'off',
        'no-unused-vars': 'off',
      },
    },
    {
      files: ['config/database.js', 'config/database_enhanced.js', 'config/email.js', 'create_oscar_broome_login_simple.js', 'e2e_perfection_test.js', 'e2e_perfection_test_final.js', 'e2e_perfection_test_final_refactored.js', 'performance_test.js', 'quantum.config.js', 'server-enhanced.js', 'server-quantum.js', 'server-simple.js', 'server_with_auth.js'],
      parser: 'espree',
      parserOptions: {
        sourceType: 'module', // Allow import/export in specific config and server files
        ecmaVersion: 2020,
      },
      rules: {
        '@typescript-eslint/no-unused-vars': 'off',
        'no-unused-vars': 'off',
      },
    },
    {
      files: ['cypress/**/*.js'],
      parser: 'espree',
      parserOptions: {
        sourceType: 'module',
        ecmaVersion: 2020,
      },
      env: {
        browser: true,
        es2021: true,
        node: true,
        jest: true,
      },
      rules: {
        '@typescript-eslint/no-unused-vars': 'off',
        'no-unused-vars': 'off',
        'no-unused-expressions': 'off', // Cypress often uses expressions in tests
      },
    },
  ],
};
