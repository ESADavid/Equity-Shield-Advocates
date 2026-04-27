# Fix TypeScript/SonarLint Errors in fix-logger-imports-fixed.js

## Steps:
- [ ] 1. Create this TODO.md
- [ ] 2. Update Node.js built-in imports to use 'node:' prefix (fs/promises, path, url)
- [ ] 3. Add explicit types: walk → AsyncGenerator<string>, fixFile → Promise<FixResult | null>, main results handling
- [ ] 4. Fix string replaceAll(), remove unnecessary await on fixFile result, type results array
- [ ] 5. Convert main() to top-level await
- [ ] 6. Apply all edits to scripts/fix-logger-imports-fixed.js via edit_file
- [ ] 7. Update TODO.md to mark completed
- [ ] 8. Verify no new errors (optional: node --check or tsc)
- [ ] 9. Task complete

**Status:** Starting implementation...

