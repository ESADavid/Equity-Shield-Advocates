# Module System Fixes - TODO

## Current Issues

- TypeScript moduleResolution "node" causing import extension errors
- Babel config using CommonJS syntax in ES module project
- Mixed require/import usage in tests
- Missing .js extensions in TypeScript relative imports

## Plan

1. Fix tsconfig.json moduleResolution to "bundler"
2. Convert babel.config.cjs to babel.config.mjs
3. Add explicit .js extensions to all TypeScript relative imports
4. Configure Jest for ES modules
5. Update test files to use consistent import syntax
6. Run tests to verify fixes

## Files to Update

- tsconfig.json
- babel.config.cjs -> babel.config.mjs
- All .ts files with relative imports
- jest.config.cjs
- Test files
