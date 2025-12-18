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
    'no-console': ['warn', { allow: ['warn', 'error'] }], // Warn on console.log, allow console.warn/error
  },
  overrides: [
    // TypeScript files - must be first to take precedence
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
    // Exclude .d.ts files from TypeScript parsing
    {
      files: ['**/*.d.ts'],
      parser: 'espree',
      parserOptions: {
        ecmaVersion: 2022,
        sourceType: 'module',
      },
      rules: {
        'no-unused-vars': 'off',
        '@typescript-eslint/no-unused-vars': 'off',
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
        '**/*.spec.js'
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
      files: ['earnings_dashboard/**/*.js', 'quantum/**/*.js', 'auth/**/*.js', 'blockchain/**/*.js', 'comprehensive_*.js', 'cypress/**/*.js', 'ecosystem.config.js', 'executive-portal/**/*.js', 'middleware/**/*.js', 'models/**/*.js', 'routes/**/*.js', 'scripts/**/*.js', 'services/**/*.js', 'staging_*.js', 'vite.config.js', 'config/**/*.js', 'frontend/**/*.js', 'blackbox_integration/**/*.js', 'ai_models/**/*.js', 'public/**/*.js', 'monitoring/**/*.js', 'owlban_revenue_repo/**/*.js'],
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
    {
      files: ['*.d.ts'],
      rules: {
        'no-unused-vars': 'off',
        '@typescript-eslint/no-unused-vars': 'off',
      }
    },
    // JavaScript files using ES modules
    {
      files: ['payrollSystem.js', 'utils/payrollCalculator.js', 'utils/payrollValidation.js'],
      parser: 'espree',
      parserOptions: {
        sourceType: 'module',
        ecmaVersion: 2022,
      },
      rules: {
        '@typescript-eslint/no-unused-vars': 'off',
        'no-unused-vars': 'off',
      },
    }
  ],
};
