# MASTER FINAL TODO - Local Code Perfection Plan

Approved plan for 100% local completion, respecting external boundaries.

## Progress Legend

- [ ] Not started
- [x] Complete
- [🔄] In progress

## Step 1: Fix .env encoding

- [ ] `node scripts/fix-env-encoding.cjs`

## Step 2: Fix logger imports (if needed)

- [ ] `node scripts/fix-logger-imports.js`
- [ ] Check output for changes

## Step 3: ESLint auto-fix

- [ ] `npx eslint . --fix`
- [ ] Verify no new errors

## Step 4: Server startup verification

- [ ] `node test_server_startup_simple.cjs`
- [ ] Confirm all systems load (non-fatal OK)

## Step 5: NPM checks

- [ ] `npm audit`
- [ ] `npm test` (quick suite if possible)

## Step 6: Update trackers

- [ ] Mark TODO.md complete
- [ ] Update QUICK_ACTION_CHECKLIST.md locals [x]
- [ ] Update REMAINING_WORK.md to 100% local
- [ ] Update NEXT_STEPS_TODO.md / TODO_PROGRESS.md

## Step 7: Verify VSCode diagnostics 0

- [ ] Restart TS server
- [ ] No ESLint/TS errors

## Completion Criteria

- [ ] All [x] above
- [ ] Server runs locally
- [ ] Ready for external (cloud/creds by owner)

**Status: Starting Step 1**
