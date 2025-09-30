# TODO: Fix Failing Jest Tests

## Completed Fixes
- [x] Fixed mocking in earnings_dashboard/fetch_and_sync_payroll.test.js: Changed fs_1.default.existsSync.mockReturnValue to jest.spyOn(fs_1.default, 'existsSync').mockReturnValue
- [x] Fixed TS syntax in earnings_dashboard/fetch_and_sync_payroll.test.ts: Changed (fs.readFileSync as jest.Mock).mockReturnValue to jest.spyOn(fs, 'readFileSync').mockReturnValue
- [x] Fixed TS syntax in payroll_server.test.ts: Removed type annotations (e: any) and (p: any)
- [x] Fixed TS syntax in quickbooks_payroll_integration.test.ts: Removed type annotation let integration: QuickBooksPayrollIntegration;
- [x] Added dummy environment variables in jest.setup.js to prevent process.exit(1) in tests
- [x] Updated Jest config to use ts-jest for all JS/TS files with useESM: true to handle ES modules and import.meta

## Remaining Issues
- [ ] Check if tests pass after these changes
- [ ] If any Babel or transform issues remain, adjust transformIgnorePatterns or babel config
- [ ] Ensure all env vars are set for all integrations (Dynamics365, QuickBooks, JPMorgan, etc.)
- [ ] Mock any remaining external dependencies if needed
- [ ] Fix any remaining syntax errors in test files

## Next Steps
- Run `npm test` or `jest` to verify fixes
- Address any new errors that appear
- Ensure all test suites pass
