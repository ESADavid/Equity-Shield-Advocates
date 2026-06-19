# Syntax Error Elimination Plan - BlackboxAI
Status: 🚀 IN PROGRESS (Approved)

## Overview
Fix 100+ lint errors from malformed console.logs, HTML tags, CJS/ESM, etc. Goal: 0 syntax errors.

## Step-by-Step Checklist

### 1. **HTML Structural Fixes** (3 files) ✅
- [x] owlbangroup.io/src/frontend/index.html (remove stray </iframe>, fix duplicate head/body)
- [x] owlbangroup.io/src/login.html (move style to head, fix tags)
- [x] owlbangroup.io/src/reverse-mergers.html (fix </head> after style)

### 2. **CJS/ESM Fixes** (3 files) [PENDING]
- [ ] scripts/execute-phase5-pilot.cjs (replace import.meta.url)
- [ ] scripts/execute-phase5-production.cjs
- [ ] scripts/execute-phase5-scaling.cjs

### 3. **Console.log Comment Fixes** (~50 test files) [PENDING]
Pattern: Replace `/* console.log(multi-line broken) */ testPassed();` → `testPassed();`
- [ ] performance_test.js (read for exact diffs)
- [ ] comprehensive_blockchain_test.js
- [ ] comprehensive_integration_test.js
- [ ] All test_*.js, scripts/load-test.js, etc. (batch via search/edit)
Batches: 10 files/step

### 4. **Specific JS Fixes** (~10 files) [PENDING]
- [ ] public/sw.js (escape literal \\n → '\\\\n')
- [ ] owlbangroup.io/src/test-azure-*.js (4 files: fix unterminated strings)
- [ ] scripts/replace-console-logs.js (emoji escapes)
- [ ] scripts/backup-production.js, scripts/complete-phase1-fixed.js, etc.

### 5. **Verification & Final** [PENDING]
- [ ] Run `npx eslint .` → 0 errors
- [ ] Run key tests: `node performance_test.js`, `node test_server_start.js`
- [ ] Update this TODO (mark ✅)
- [ ] Git commit to blackboxai/fix-syntax branch
- [ ] 🎉 Complete!

## Progress Tracker
- Fixed: 0/100 errors
- Current batch: HTML

Run `node scripts/fix-syntax-errors.js` if auto-fixer exists post-fixes.

