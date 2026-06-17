# EquityShield Advocates Integration TODO

- [x] Add EquityShield Advocates-specific integration builder in `src/services/bankingSetupService.js`
- [x] Add route `POST /api/banking/setup/equityshield-advocates` in `src/routes/bankingRoutes.js`
- [x] Add test payload fixture for EquityShield Advocates integration in `tests/`
- [ ] Execute API validation checks for new route and summarize results

# Production Environment TODO

- [x] Create `.env.production.example` template with secure defaults
- [x] Add PM2 production process file `ecosystem.config.cjs`
- [x] Add startup scripts `scripts/start-production.ps1` and `scripts/start-production.sh`
- [x] Document production runbook and restart behavior in `README.md`
- [ ] Run production-mode smoke test (`NODE_ENV=production`) for `/health` and EquityShield endpoint
