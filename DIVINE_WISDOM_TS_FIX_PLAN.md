# DivineWisdom TS Fix Plan

## Information Gathered

After analyzing the `algorithms/divineWisdom.js` file and the TODO requirements, I've identified the following issues that need fixing:

### Current File Structure
- JSDoc type definitions at top (lines 1-80) - need proper @typedef and type annotations
- Class `DivineWisdom` with multiple methods requiring type fixes
- JSDoc comments exist but lack proper TypeScript-style type annotations in function params

### Issues Identified

1. **Index Signature Errors** (keyword, principle, key types):
   - `alignmentIndicators[keyword]` - needs proper typing
   - `kingdomPrinciples[principle]` - dynamic key access
   - `factors[key]` - dynamic key access
   - `e.theme` - needs proper type

2. **Property/Type Errors**:
   - `warnings` should be `Warning[]`
   - `blessings` should be `Blessing[]`
   - `wisdomLevel` missing in Evaluation type
   - `decision.attributes` needs proper typing

3. **Implicit Any Parameters** - All function parameters need explicit types:
   - `evaluateDecision(decision, context)`
   - `evaluatePrinciple(decision, principle, context)`
   - `checkKingdomAlignment(decision, principle)`
   - All evaluate*Factor functions
   - `recognizePropheticPatterns(events)`
   - And more...

4. **SonarLint Issues**:
   - Line ~190: Replace `Object.prototype.hasOwnProperty.call()` with `Object.hasOwn()`
   - Line ~498: Replace `!isNaN(d)` with `Number.isNaN(d)`
   - Line ~509: Replace array `.includes()` with `Set` for sacredNumbers

## Plan

### Step 1: Add proper JSDoc type definitions at top of file
- Convert existing @typedef blocks to proper TypeScript-compatible JSDoc
- Add @param and @returns types to all functions
- Ensure all custom types are properly defined

### Step 2: Fix index signature errors
- Add proper type annotations for dynamic keys (keyword, principle, key)
- Use string | number types where appropriate

### Step 3: Fix warnings/blessings array types
- Ensure Warning[] and Blessing[] types are properly used

### Step 4: Fix wisdomLevel property in evaluation
- Add wisdomLevel to Evaluation type definition

### Step 5: Fix decision.attributes type issues
- Ensure Record<string, number> type is properly applied

### Step 6: Fix implicit any on all function parameters
- Add explicit type annotations to ALL function parameters
- This is the largest fix - many functions need parameter types

### Step 7: Fix SonarLint issues
- Replace `Object.prototype.hasOwnProperty.call()` with `Object.hasOwn()`
- Replace `!isNaN(d)` with `Number.isNaN(d)`
- Replace array includes with Set for sacredNumbers

### Step 8: Test compilation
- Run TypeScript compiler to verify all fixes

## Files to be Edited

- `algorithms/divineWisdom.js` - Main file requiring all fixes

## Followup Steps

1. After edits complete, run `npx tsc --noEmit` to verify TypeScript compilation
2. Check for any remaining errors
3. Update DIVINE_WISDOM_TODO.md with completion status
