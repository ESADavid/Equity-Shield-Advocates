# Jest ESM Parse Error Fix Plan

- [x] Inspect current Jest and Babel configuration (`jest.config.js`, `babel.config.cjs`)
- [x] Update `jest.config.js` for `oscar-broome` so Babel transforms `.js` ESM tests reliably
- [x] Update `babel.config.cjs` test env to compile modules for Jest runtime compatibility
- [ ] Run filtered Jest command to verify ESM parse errors are resolved
- [ ] Review remaining failures (if any) and summarize next actionable fixes
