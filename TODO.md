# ESLint Fixes TODO

## Phase 1: Core Config (Current)
- [x] 1. Update .eslintrc.json with Cypress override

## Phase 2: Cypress Globals
- [ ] 2. Add global comments to 7 e2e/*.cy.js
- [ ] 3. Add to support/e2e.js & commands.js

## Phase 3: Require Fixes (High Impact)
- [ ] 4. docs/docusaurus.config*.js dynamic import
- [ ] 5. jest*.js disable rule

## Phase 4: Cleanup
- [ ] 6. Remove unused imports (server.js, dashboard-server.js etc.)
- [ ] 7. Fix console.logs in tests
- [ ] 8. public/sw.js parsing

## Phase 5: Verify
- [ ] 9. Run npm run lint (0 errors)
- [ ] 10. Test Cypress run

