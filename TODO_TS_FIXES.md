# TODO: Fix TypeScript Errors and SonarLint Issues

## Tasks

- [x] Fix `sanitizeEmployeeInput` in `utils/payrollValidation.ts` to properly handle optional properties for `exactOptionalPropertyTypes`
- [x] Refactor `validateEmployeeInput` in `utils/payrollValidation.ts` to reduce cognitive complexity by extracting validation logic
- [x] Refactor `validatePayrollCalculationInput` in `utils/payrollValidation.ts` to reduce cognitive complexity by extracting validation logic
- [x] Change `String.replace` to `replaceAll` in `sanitizeEmployeeInput` function
- [x] Change `isNaN` to `Number.isNaN` in `isValidPayPeriod` function
- [x] Update `tsconfig.json` to remove deprecated options and add `"ignoreDeprecations": "5.0"`
- [x] Make `dynamicsBaseUrl` and `accessToken` readonly in `payroll_integration.ts`
- [x] Remove unused `res` parameter in middleware in `payroll_server.ts`
- [x] Fix test in `quickbooks_payroll_integration.test.ts` to throw Error instead of string for rejection
- [x] Fix module declaration issues in `config/logger.d.ts` and `earnings_dashboard/payroll_api.d.ts`

## Followup Steps

- [x] Run TypeScript compilation to verify no errors
- [x] Run tests to ensure functionality is preserved
- [x] Check for any remaining linter issues
