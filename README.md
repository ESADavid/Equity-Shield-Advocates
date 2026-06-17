# Equity Shield Advocates - JPM Integration Artifacts

Secure Node/Express JPM integration implementation covering:

- Option A: Code artifact verification
- Option B: Local run
- Option C: Curl matrix testing
- Option D: Logging + secret controls

## Setup

1. Install dependencies:

```bash
npm install
```

1. Copy environment file:

```bash
cp .env.example .env
```

(Windows PowerShell)

```powershell
Copy-Item .env.example .env
```

1. Fill required values in `.env`:

- `JPM_CLIENT_ID`
- `JPM_CLIENT_SECRET`
- `JPM_SCOPE`
- `INTERNAL_API_KEY`

1. Start service:

```bash
npm run start
```

## Endpoints

- `GET /health`
- `POST /api/oauth/token`
- `POST /api/banking/setup`
- `POST /api/banking/setup/family-trust`
- `POST /api/banking/setup/equityshield-advocates`
- `GET /api/jpm/ping` (requires `Authorization: Bearer <INTERNAL_API_KEY>` or `x-api-key`)

## Production Environment

1. Create production env file from template:
   - `.env.production.example` -> `.env.production`
2. Set secure production values:
   - `JPM_CLIENT_ID`
   - `JPM_CLIENT_SECRET`
   - `INTERNAL_API_KEY`
   - production JPM URLs/scope approved by bank
3. Start in production mode:
   - Windows PowerShell:
     - `./scripts/start-production.ps1`
   - Unix:
     - `sh ./scripts/start-production.sh`
4. Optional PM2 process manager:
   - `pm2 start ecosystem.config.cjs`
   - `pm2 logs equity-shield-advocates-api`
5. Restart requirement after route/code updates:
   - Restart the running Node process so new endpoints are loaded.

## Security Controls

- Required env var validation in `src/config/env.js`
- `.env` ignored by git
- Structured logs with redaction
- Centralized error handling with request IDs
- Safe upstream error mapping

## System Topology

- `docs/TOPOLOGY.md` - architecture, middleware, route/service flow, and security boundaries

## Test Matrix

See:

- `tests/curl_matrix.md`
- `tests/expected_results.md`
- `scripts/test_api_matrix.ps1` (Windows)
- `scripts/test_api_matrix.sh` (Unix)
