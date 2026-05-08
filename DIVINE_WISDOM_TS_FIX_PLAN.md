# DIVINE WISDOM TypeScript Fix Plan

## Summary of Errors Found in divineWisdom.js

### Type Error Categories

1. **Implicit 'any' Type Errors** (Parameter type annotations missing)
   - Line 234: `evaluatePrinciple(decision, principle, context)` - parameters need types
   - Line 284: `checkKingdomAlignment(decision, principle)` - parameters need types
   - Line 252, 260, 268: Various callback parameters need types
   - Line 323, 336, 353, 369, 386, 404, 417, 464, 475, 486, 492, 501, 505, 507, 524, 554, 575, 637, 645, 654: Multiple function parameters

2. **Index Signature Errors** (Cannot index type 'Object')
   - Line 217: `decision[principle]` - decision typed as Object
   - Line 248, 366, 401, 436: Indexing kingdomPrinciples with dynamic keys

3. **Property Does Not Exist Errors**
   - Line 220-221: `decision.attributes` - attributes property doesn't exist on Object
   - Line 456-459: Spiritual factors (prayer, peace, confirmation, alignment) on Object
   - Line 556, 564: 'factors' and 'events' on empty object {}

4. **SonarLint Suggestions**
   - Line 216: Use Object.hasOwn() instead of hasOwnProperty.call()
   - Line 220: 'If' statement should not be the only statement in 'else' block
   - Line 220: Prefer optional chain expression
   - Line 284: 'decision' is declared but never read
   - Line 524: Prefer Number.isNaN over isNaN
   - Line 535: sacredNumbers should be a Set

## Fix Strategy

### Step 1: Add Proper Type Annotations

Add JSDoc @param tags with proper types to all functions

### Step 2: Add Type Definitions at Top

Create interface definitions for:

- Decision interface
- DecisionContext interface  
- Scores interface

### Step 3: Fix Index Signatures

Use proper type casting or index signatures

### Step 4: Fix SonarLint Issues

- Use Object.hasOwn() for property checks
- Use optional chaining
- Convert sacredNumbers to Set
- Use Number.isNaN

## Files to Edit

- `algorithms/divineWisdom.js` - Main file with all fixes

## Implementation Order

1. Add interface definitions at top of file
2. Fix evaluatePrinciple method (line 234)
3. Fix checkKingdomAlignment method (line 284)
4. Fix multiFactorWisdomScore (line 417)
5. Fix evaluateSpiritualFactor (line 456)
6. Fix remaining parameter types
7. Fix SonarLint issues
