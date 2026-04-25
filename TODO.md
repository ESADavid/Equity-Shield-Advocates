# ESLint Fixes Progress Tracker (Target: 0 warnings/errors)
Status: In Progress | Plan: [Approved](#)

## Batch 1: Test Files - Remove console.logs (~500 fixes)
- [ ] comprehensive_payroll_test.js
- [ ] comprehensive_integration_test.js
- [ ] comprehensive_merchant_test.js
- [ ] comprehensive_blockchain_test.js
- [ ] comprehensive_treasury_test.js
- [ ] critical_path_test.js
- [ ] performance_test.js
- [ ] comprehensive_payroll_test_updated.js
- [ ] All other *_test.js / comprehensive_*.js (use search_files if needed)

## Batch 2: Unused Logger Vars (~50 fixes)
- [ ] OWLBAN-GROUP-RECORDS/backend/server.js
- [ ] fix_markdown_lint.js / .cjs
- [ ] Partial logger files (script.js, etc.)

## Batch 3: Cypress Fixes (~10)
- [ ] owlbangroup.io/cypress/e2e/auth.cy.js
- [ ] owlbangroup.io/cypress/support/e2e.js
- [ ] owlbangroup.io/cypress/support/commands.js
- [ ] accessibility.cy.js / error-scenarios.cy.js

## Batch 4: require→import / no-require-imports (~10)
- [ ] owlbangroup.io/script.js (showdown)
- [ ] jest.setup.js / jest-environment-setup.js
- [ ] docs/docusaurus.config*.js

## Batch 5: Parsing / no-undef / expressions (~20)
- [ ] public/sw.js (unicode escape)
- [ ] earnings_dashboard/src/ErrorRecovery.jsx (logger expr)
- [ ] owlbangroup.io/script.js (fbq/gtag/showdown/update*)
- [ ] routes/debtAcquisitionRoutes.js (parsing)
- [ ] scripts/backup-production.js / implement-all-phases.js / setup-production-db.js

## Verification
- [ ] Run `npx eslint . --max-warnings 0`
- [ ] Run `npm test`
- [ ] Create branch `blackboxai/eslint-fixes`, commit, gh pr

**Next:** Batch 1 test files (read + edit comprehensive_payroll_test.js first)

