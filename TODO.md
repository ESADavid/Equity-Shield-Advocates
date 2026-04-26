# ESLint Full Fix TODO

## Steps:
- [ ] 1. Install npm dependencies (`npm ci`)
- [ ] 2. Fix .eslintrc.cjs parserOptions
- [ ] 3. Run `npm run lint:fix`
- [ ] 4. Generate JSON report `npm run lint --format json > eslint_fix_output.json`
- [ ] 5. Verify `npm run lint` (expect 0 parse errors, reduced warnings)
- [ ] 6. Update tests if needed
- [ ] 7. Commit changes

**Status: Starting step 1**

