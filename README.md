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

2. Copy environment file:

```bash
cp .env.example .env
```
(Windows PowerShell)
```powershell
Copy-Item .env.example .env
```

3. Fill required values in `.env`:

- `JPM_CLIENT_ID`
- `JPM_CLIENT_SECRET`
- `JPM_SCOPE`
- `INTERNAL_API_KEY`

4. Start service:

```bash
npm run start
```

## Endpoints

- `GET /health`
- `POST /api/oauth/token`
- `POST /api/banking/setup`
- `GET /api/jpm/ping` (requires `Authorization: Bearer <INTERNAL_API_KEY>` or `x-api-key`)

## Security Controls

- Required env var validation in `src/config/env.js`
- `.env` ignored by git
- Structured logs with redaction
- Centralized error handling with request IDs
- Safe upstream error mapping

## Test Matrix

See:

- `tests/curl_matrix.md`
- `tests/expected_results.md`
- `scripts/test_api_matrix.ps1` (Windows)
- `scripts/test_api_matrix.sh` (Unix)
