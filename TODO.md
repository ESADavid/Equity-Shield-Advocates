# EquityShield Advocates Integration TODO

- [x] Add EquityShield Advocates-specific integration builder in `src/services/bankingSetupService.js`
- [x] Add route `POST /api/banking/setup/equityshield-advocates` in `src/routes/bankingRoutes.js`
- [x] Add test payload fixture for EquityShield Advocates integration in `tests/`
- [x] Execute API validation checks for new route and summarize results

## Production Environment TODO

- [x] Create `.env.production.example` template with secure defaults
- [x] Add PM2 production process file `ecosystem.config.cjs`
- [x] Add startup scripts `scripts/start-production.ps1` and `scripts/start-production.sh`
- [x] Document production runbook and restart behavior in `README.md`
- [x] Run production-mode smoke test (`NODE_ENV=production`) for `/health`
  and EquityShield endpoint
  - Result: `GET /health` returned `200 OK`; `POST /api/banking/setup/equityshield-advocates`
    returned `200 OK` with valid fixture and `400 Bad Request` with invalid fixture.

## Banking Operations Documentation TODO

- [x] Set up distinct account topology guidance for clean controls and
  reporting in `EquityShield_Banking_Operations_Guide.md`
- [x] Add account-level control ownership and reporting tags
- [x] Mark account topology checklist item complete
- [x] Assign named roles in Section 2 and create assigned control baseline
- [x] Set up Section 3 real estate banking workflow with ownership gates,
  go/no-go rules, and control-baseline checklist
- [x] Build Section 4 Real Estate Acquisition/Project Account operating guide
  and shift downstream section numbering
