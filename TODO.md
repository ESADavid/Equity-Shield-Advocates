# Remaining Coverage TODO

- [ ] Start isolated server on port 8081 with explicit env injection
- [ ] Re-test auth happy-path (A) on `/api/banking/transactions` and `/api/banking/ping`
- [ ] Re-test mixed-header precedence (B) on both protected endpoints
- [ ] Run OAuth missing-config isolated scenario (C) with one JPM_* unset and verify 400 + details
- [ ] Run OAuth timeout/unreachable distinction tests (D)
- [ ] Re-test malformed JSON normalization (E) expecting `Malformed JSON body`
- [ ] Summarize all outcomes for A/B/C/D/E/F
