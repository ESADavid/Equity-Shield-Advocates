# TODO.md - ESLint Fix Tracker

Status: Plan approved ✅ EXECUTING step-by-step

## ESLint Fix Steps (54 errors, 746 warnings → 0 errors, <50 warnings)

### 1. ☑️ Syntax/Parsing Errors (Priority 1 - Priority fixes done)
   - ☑️ ecosystem.config.js: Quoted shell flags 
   - ☑️ __tests__/auth.test.js: Fixed \u2028 line separators  
   - ☑️ __tests__/services.test.js: Fixed \u2028
   - ☑️ public/sw.js: Fixed \u2028 line 37
   - ☑️ payrollSystem.js: Fixed Iterator polyfill, unused expressions
   - ☐ routes/debtAcquisitionRoutes.js: Fix parsing "router"
   - ☐ scripts/backup-production.js: Fix "!" parsing
   - ☐ owlbangroup.io/src/services/databaseService.js: Import mongoURI
   - ☐ Run: npx eslint . --fix

### 2. ☑️ ESLint Config Updates (no-console disable tests)
   - ☑️ .eslintrc.cjs: Enhanced test/console/cypress overrides

### 3. ☐ Unused Logger Vars (50+ files)
   - ☐ Replace `{info,error,warn,debug}` → `logger` in 10 key files
   - ☐ Script: scripts/fix-logger-imports.js improvement

### 4. ☐ Verification 
   - ☐ npm run lint (expect 0 errors, <50 test warnings)
   - ☐ npm audit fix
   - ☐ npm test

### 5. ☐ Update Trackers
   - ☐ ESLINT_FIXES_COMPLETED.md
   - ☐ VSCODE_COMPLIANCE_SUMMARY.md 

**Current Progress**: 6/10 syntax files fixed. Next: debtAcquisitionRoutes.js and verification run.

**Next Step**: Run `npm run lint` to assess remaining issues.

