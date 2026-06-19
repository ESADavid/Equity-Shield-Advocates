# Dashboard.ts Fix Plan

## Error List and Fix Strategy

### 1. Line 16: `Property 'register' does not exist on type 'typeof Chart'`
**Issue:** The type definition declares `register` as a const, not a static method on Chart class
**Fix:** Update `types/chart.js.d.ts` to add register as a static method on Chart class

### 2. Lines 62, 64, 92, 96: `'earningsData' is possibly 'null'`
**Issue:** TypeScript strict null check errors
**Fix:** Add null checks using optional chaining (`?.`) and conditional rendering

### 3. Line 103: Type `{ responsive: boolean; plugins: { legend: { position: string; }; ... }` is not assignable to type 'ChartOptions'
**Issue:** String literal type required for position
**Fix:** Use type assertion `as 'top'` or update the type definition to accept string

### 4. Line 148: Missing properties from type PlaidLink
**Issue:** Component expects many required props
**Fix:** Update the PlaidLink component props to make optional props truly optional in the type definition

### 5. Lines 157, 169: Parameter implicitly has 'any' type
**Issue:** Callback parameters lack type annotations
**Fix:** Add proper type annotations: `(data: any, metadata: any) => void`

### 6. Lines 181-182: Property 'name', 'type', 'subtype', 'balances' does not exist on type 'never'
**Issue:** Account type inference is too narrow  
**Fix:** Define proper Account interface and use it for the array

### 7. Line 1: 'React' is declared but its value is never read
**Issue:** React is imported but JSX transform handles it
**Fix:** Remove React import or configure JSX

### 8. Line 158: TODO comment
**Issue:** Incomplete implementation
**Fix:** Replace TODO with proper logging implementation

### 9. Line 159: Prefer optional chain
**Issue:** Can be simplified
**Fix:** Use optional chaining: `data?.accounts`

### 10. Line 180: Do not use Array index in keys
**Issue:** Using array index as key is not recommended
**Fix:** Use a unique identifier like `account.id` or `index` with a prefix

## Files to Edit

1. `types/chart.js.d.ts` - Fix Chart.register type definition
2. `earnings_dashboard/src/Dashboard.jsx` - Fix all TypeScript errors
3. `earnings_dashboard/src/PlaidLink.jsx` - Update prop types if needed

## Execution Order

1. First fix `types/chart.js.d.ts` to proper declare Chart.register
2. Then fix `Dashboard.jsx` with all null checks, types, and other fixes
3. Verify all errors are resolved
