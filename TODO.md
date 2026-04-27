## Steps (Logical breakdown from approved plan)

### 1. Safe CLI Fixes [x]
- [x] node scripts/fix-env-encoding.cjs (UTF-8 .env)
- [x] npx eslint . --fix (auto lint fixes)  
- [x] npm audit fix --audit-level=moderate (safe deps)

### 2. Logger/Console Replacement [ ]
- [ ] Add testReporter imports + ESLint disable to ALL test files (*.test.js/ts/cjs)
- [ ] Fix syntax/parsing errors in top test files (comprehensive_payroll_test*.js, critical_path_test.js, comprehensive_merchant_test.js, etc.)
- [ ] Replace console.log → logger calls in non-test files (Dashboard.jsx, LayerOnboarding.jsx, scripts)
- [ ] Fix payroll_server.js logger import
- [ ] Update .eslintrc.cjs for no-console exceptions in tests
- [ ] Run `npx eslint . --fix` verify fixes

### 3. Error Handling Integration [ ]

### 4. TS/Sonar Fixes [ ]

### 5. Syntax/HTML Fixes [ ]

### 6. Verification [ ]
- [ ] node test_server_startup_simple.cjs
- [ ] npx tsc --noEmit
- [ ] npm test (minimal)

### 7. Docs Finalization [ ]
- [x] all TODO MDs
- [ ] VSCode 0 diagnostics

**Progress: 1/7**
**Last Updated:** $(date)
