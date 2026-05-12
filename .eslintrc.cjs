module.exports = {
  env: {
    browser: true,
    es2021: true,
    node: true,
    jest: true,
  },
  extends: ['eslint:recommended'],
  parser: 'espree',
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
  },
  ignorePatterns: [
    '**/*.d.ts', // Ignore all TypeScript declaration files
    'node_modules/',
    'dist/',
    'build/',
    'coverage/',
    '*.min.js',
  ],
globals: {
    logger: 'readonly', // Define logger as a global variable
    testPassed: 'readonly', // Test reporter utility
    testFailed: 'readonly', // Test reporter utility
    logTest: 'readonly', // Test reporter utility
  },
  rules: {
    'no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
    'no-undef': 'error',
    'no-case-declarations': 'off', // Allow declarations in case blocks
    'no-dupe-keys': 'error',
    'no-prototype-builtins': 'warn',
    'prefer-const': 'error',
    'no-useless-escape': 'warn',
    'no-unused-expressions': 'error',
    'no-console': ['warn', { allow: ['warn', 'error'] }], // Warn on console.log, allow console.warn/error
  },
  overrides: [
    // Files with ES module syntax that need module sourceType - MUST BE FIRST
    {
      files: [
        'algorithms/**/*.js',
        'app.js',
        'check_credentials.js',
        'setup_credentials.js',
        'setup_jpmorgan_credentials.js',
        'simple_jpmorgan_validation.js',
        'delete_babel_config_cjs.js',
        'diagnose_integration.js',
      ],
      parser: 'espree',
      parserOptions: {
        sourceType: 'module',
        ecmaVersion: 2022,
      },
      rules: {
        'no-unused-vars': 'off',
      },
    },
    // TypeScript files
    {
      files: ['**/*.ts'],
      parser: '@typescript-eslint/parser',
      parserOptions: {
        ecmaVersion: 2022,
        sourceType: 'module',
        project: './tsconfig.json',
        tsconfigRootDir: __dirname,
      },
      plugins: ['@typescript-eslint'],
      extends: ['plugin:@typescript-eslint/recommended'],
      rules: {
        '@typescript-eslint/no-unused-vars': 'off',
        '@typescript-eslint/no-explicit-any': 'off',
        '@typescript-eslint/no-require-imports': 'off',
        '@typescript-eslint/no-inferrable-types': 'off',
        '@typescript-eslint/explicit-function-return-type': 'off',
        '@typescript-eslint/explicit-module-boundary-types': 'off',
        '@typescript-eslint/no-empty-function': 'off',
        '@typescript-eslint/no-empty-interface': 'off',
        'no-unused-vars': 'off',
      },
    },
    // JSX and React files
    {
      files: ['**/*.jsx', '**/*.tsx'],
      parserOptions: {
        ecmaFeatures: {
          jsx: true,
        },
      },
      rules: {
        'no-unused-vars': 'off',
        'no-undef': 'off', // React and JSX globals handled by environment
      },
    },
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
    // Specific test file with Chai assertions
    {
      files: ['**/test_jpmorgan_auth_integration.js'],
      parser: 'espree',
      parserOptions: {
        sourceType: 'module',
        ecmaVersion: 2022,
      },
      rules: {
        '@typescript-eslint/no-unused-vars': 'off',
        '@typescript-eslint/no-unused-expressions': 'off', // Allow Chai assertions
        'no-unused-vars': 'off',
        'no-unused-expressions': 'off', // Allow Chai assertions
        'no-console': 'off', // Allow console in tests
      },
    },
    // All test files - merged configuration
{
      files: [
        'tests/**/*.js',
        'test/**/*.js',
        'test/**/*.mjs',
        'test/**/*.cjs',
        'debt_acquisition_critical_test.js',
        'debt_acquisition_test.js',
        '**/test_*.js',
        '**/*.test.js',
        '**/*.spec.js',
        'comprehensive_*.js',
        'comprehensive_*.ts',
      ],
      parser: 'espree',
      parserOptions: {
        sourceType: 'module', // Allow import/export in test files
        ecmaVersion: 2022, // Allow top-level await
      },
      rules: {
        '@typescript-eslint/no-unused-vars': 'off',
        'no-unused-vars': 'off',
        'no-unused-expressions': 'off', // Allow Chai assertions in tests
        'no-console': 'off', // Allow console in test files
      },
    },
    {
      files: [
        'earnings_dashboard/**/*.js',
        'quantum/**/*.js',
        'auth/**/*.js',
        'blockchain/**/*.js',
        'comprehensive_*.js',
        'cypress/**/*.js',
        'ecosystem.config.js',
        'executive-portal/**/*.js',
        'middleware/**/*.js',
        'models/**/*.js',
        'routes/**/*.js',
        'scripts/**/*.js',
        'services/**/*.js',
        'staging_*.js',
        'vite.config.js',
        'config/**/*.js',
        'frontend/**/*.js',
        'blackbox_integration/**/*.js',
        'ai_models/**/*.js',
        'public/**/*.js',
        'monitoring/**/*.js',
        'owlban_revenue_repo/**/*.js',
      ],
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
      files: [
        'config/database.js',
        'config/database_enhanced.js',
        'config/email.js',
        'create_oscar_broome_login_simple.js',
        'e2e_perfection_test.js',
        'e2e_perfection_test_final.js',
        'e2e_perfection_test_final_refactored.js',
        'performance_test.js',
        'quantum.config.js',
        'server-enhanced.js',
        'server-quantum.js',
        'server-simple.js',
        'server_with_auth.js',
      ],
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
      globals: {
        cy: 'readonly',
        Cypress: 'readonly',
        expect: 'readonly',
        assert: 'readonly',
      },
      rules: {
        '@typescript-eslint/no-unused-vars': 'off',
        'no-unused-vars': 'off',
        'no-unused-expressions': 'off', // Cypress often uses expressions in tests
        'no-console': 'off', // Allow console in Cypress tests
      },
    },
    // JavaScript files using ES modules
    {
      files: ['payrollSystem.js', 'utils/**/*.js'],
      parser: 'espree',
      parserOptions: {
        sourceType: 'module',
        ecmaVersion: 2022,
      },
      rules: {
        '@typescript-eslint/no-unused-vars': 'off',
        'no-unused-vars': 'off',
      },
    },
  ],
};
