# Syntax Error Fixes TODO

## Overview
Fix malformed console.log replacements causing Prettier/lint failures. Patterns: unterminated strings, extra parens, broken arrows.

## Steps
- [ ] 1. Create scripts/fix-syntax-errors.js for global safe replacements
- [ ] 2. performance_test.js: Fix template literals, remove import.meta check
- [ ] 3. owlbangroup.io/test-industry-filtering.js: Fix map arrow breaks, unterminated
- [ ] 4. public/sw.js: Escape \n in string
- [ ] 5. scripts/backup-production.js: Remove shebang, fix logger
- [ ] 6. routes/debtAcquisitionRoutes.js: Remove duplicate route block
- [ ] 7. test_analytics_api.js: Fix logFail unterminated
- [ ] 8. simple_jpmorgan_test.js: Fix unterminated quotes
- [ ] 9. Fix remaining test_*.js via pattern or script
- [ ] 10. `npx prettier --write .`
- [ ] 11. `npm run lint`
- [ ] 12. `node scripts/complete-phase1.js`
- [ ] 13. Update this TODO

Progress: Starting step 1
