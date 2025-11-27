module.exports = {
  env: {
    browser: true,
    es2021: true,
    node: true,
    jest: true,
  },
  extends: [
    'eslint:recommended',
  ],
  parser: 'espree',
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
  },
  rules: {
    'no-unused-vars': ['warn', { 'argsIgnorePattern': '^_' }],
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
      files: ['owlban_revenue_repo/**/*.js'],
      parser: 'espree',
      parserOptions: {
        sourceType: 'module',
        ecmaVersion: 2022,
      },
      rules: {
        '@typescript-eslint/no-unused-vars': 'off',
        '@typescript-eslint/no-unused-expressions': 'off',
        'no-unused-vars': 'off',
        'no-unused-expressions': 'off',
      },
    },
    {
      files: ['owlban_revenue_repo/executive-portal/**/*.js'],
      parser: 'espree',
      parserOptions: {
        sourceType: 'script',
        ecmaVersion: 2022,
      },
      rules: {
        '@typescript-eslint/no-unused-vars': 'off',
        'no-unused-vars': 'off',
      },
    },
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
      files: ['**/test_jpmorgan_auth_integration.js'],
      parser: 'espree',
      parserOptions: {
        sourceType: 'module',
        ecmaVersion: 2022,
      },
      rules: {
        '@typescript-eslint/no-unused-vars': 'off',
        '@typescript-eslint/no-unused-expressions': 'off', // Allow Chai assertions in this test file
        'no-unused-vars': 'off',
        'no-unused-expressions': 'off', // Allow Chai assertions in this test file
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
        'no-unused-expressions': 'off', // Allow Chai assertions in tests
      },
    },
    {
      files: ['earnings_dashboard/**/*.js', 'quantum/**/*.js', 'auth/**/*.js', 'blockchain/**/*.js', 'comprehensive_*.js', 'cypress/**/*.js', 'ecosystem.config.js', 'executive-portal/**/*.js', 'middleware/**/*.js', 'models/**/*.js', 'routes/**/*.js', 'scripts/**/*.js', 'services/**/*.js', 'staging_*.js', 'test_*.js', 'vite.config.js', 'config/**/*.js', 'frontend/**/*.js', 'blackbox_integration/**/*.js', 'ai_models/**/*.js', 'public/**/*.js', 'monitoring/**/*.js', 'test/**/*.js', 'owlban_revenue_repo/**/*.js'],
      parser: 'espree',
      parserOptions: {
        sourceType: 'module', // Allow import/export in various module files
        ecmaVersion: 2022,
      },
      rules: {
        '@typescript-eslint/no-unused-vars': 'off',
        '@typescript-eslint/no-unused-expressions': 'off',
        'no-unused-vars': 'off',
        'no-unused-expressions': 'off',
      },
    },
    {
      files: ['config/database.js', 'config/database_enhanced.js', 'config/email.js', 'create_oscar_broome_login_simple.js', 'e2e_perfection_test.js', 'e2e_perfection_test_final.js', 'e2e_perfection_test_final_refactored.js', 'performance_test.js', 'quantum.config.js', 'server-enhanced.js', 'server-quantum.js', 'server-simple.js', 'server_with_auth.js'],
      parser: 'espree',
      parserOptions: {
        sourceType: 'module', // Allow import/export in specific config and server files
        ecmaVersion: 2022,
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
    {
      files: ['*.d.ts'],
      rules: {
        'no-unused-vars': 'off',
        '@typescript-eslint/no-unused-vars': 'off',
      }
    }
  ],
};
