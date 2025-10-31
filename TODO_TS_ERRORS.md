# TODO: Fix TypeScript Errors and SonarLint Issues

## Tasks

- [x] Fix `sanitizeEmployeeInput` in `utils/payrollValidation.ts` to properly handle optional properties for `exactOptionalPropertyTypes`
- [x] Refactor `validateEmployeeInput` in `utils/payrollValidation.ts` to reduce cognitive complexity by extracting validation logic
- [x] Refactor `validatePayrollCalculationInput` in `utils/payrollValidation.ts` to reduce cognitive complexity by extracting validation logic
- [x] Change `String.replace` to `replaceAll` in `sanitizeEmployeeInput` function
- [x] Change `isNaN` to `Number.isNaN` in `isValidPayPeriod` function
- [x] Update `tsconfig.json` to remove deprecated `moduleResolution` and `baseUrl` options and add `"ignoreDeprecations": "6.0"`
- [x] Make `dynamicsBaseUrl` and `accessToken` readonly in `payroll_integration.ts`
- [x] Remove unused `res` parameter in middleware in `payroll_server.ts`
- [x] Fix test in `quickbooks_payroll_integration.test.ts` to throw Error instead of string for rejection

## Followup Steps

- [ ] Run TypeScript compilation to verify no errors
- [ ] Run tests to ensure functionality is preserved
- [ ] Check for any remaining linter issues
