# NPM Security Audit Fix TODO

## Overview
Fix 5 high vulnerabilities from `npm audit`:
- semver via nodemon (requires targeted update)
- tar via @mapbox/node-pre-gyp (npm audit fix)

**Progress: 0/5 complete**

## Step 1: Non-breaking fixes [PENDING]
- Run `npm audit fix`
- Expected: Fixes tar vulnerabilities

## Step 2: Update nodemon [PENDING]
- `npm install nodemon@^3.1.14 --save-dev`
- Updates from vulnerable 2.0.20 to safe 3.1.14

## Step 3: Verify resolution [PENDING]
- `npm audit`
- Goal: 0 vulnerabilities

## Step 4: Test dev server [PENDING]
- `npm run dev`
- Confirm server-enhanced.js starts without nodemon issues

## Step 5: Commit & document [PENDING]
- git add/commit package*.json
- Update main TODO.md: Mark NPM vulnerabilities ✅ FIXED

