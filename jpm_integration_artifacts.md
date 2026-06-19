# JPM Integration Code Artifacts (Options A/B/C/D)

This document defines concrete code artifacts to implement a secure JPMorgan integration for Equity Shield Advocates, aligned to:

- **A)** Verify actual code artifacts exist for JPM integration  
- **B)** Run service locally  
- **C)** Execute full curl test matrix for impacted endpoints (happy/error/edge)  
- **D)** Validate side effects/logging + secret-handling controls  

---

## 1) Project Structure

```text
.
├─ package.json
├─ .env.example
├─ README.md
├─ scripts/
│  ├─ test_oauth_happy.sh
│  ├─ test_oauth_error.sh
│  ├─ test_api_matrix.sh
│  └─ test_api_matrix.ps1
├─ src/
│  ├─ server.js
│  ├─ config/
│  │  └─ env.js
│  ├─ middleware/
│  │  ├─ requestId.js
│  │  ├─ authGuard.js
│  │  └─ errorHandler.js
│  ├─ services/
│  │  ├─ jpmOAuthService.js
│  │  ├─ jpmApiClient.js
│  │  └─ bankingSetupService.js
│  ├─ routes/
│  │  ├─ healthRoutes.js
│  │  ├─ oauthRoutes.js
│  │  └─ bankingRoutes.js
│  └─ utils/
│     ├─ logger.js
│     └─ redact.js
└─ tests/
   ├─ curl_matrix.md
   └─ expected_results.md
```

---

## 2) Environment Contract (`.env.example`)

```env
# Server
PORT=8080
NODE_ENV=development

# JPM OAuth
JPM_OAUTH_URL=https://id.payments.jpmorgan.com/am/oauth2/alpha/access_token
JPM_CLIENT_ID=
JPM_CLIENT_SECRET=
JPM_SCOPE=jpm:payments:sandbox
JPM_GRANT_TYPE=client_credentials

# Optional API base (sandbox)
JPM_API_BASE_URL=https://api-sandbox.payments.jpmorgan.com

# Security / ops
LOG_LEVEL=info
REQUEST_TIMEOUT_MS=15000
ENABLE_VERBOSE_ERRORS=false
```

**Security rule:** Never commit real credentials. Secrets only in environment variables or secret manager.

---

## 3) API Endpoints (Artifact Specification)

### Health

- `GET /health`
  - Returns uptime, environment, version, timestamp.

### OAuth Token

- `POST /api/oauth/token`
  - Triggers client-credentials token request to JPM OAuth.
  - Response includes sanitized metadata (never echo secrets).

### Banking Setup Workflow

- `POST /api/banking/setup`
  - Accepts entity payload (`entityName`, `ein`, `authorizedSigners`, `accounts`).
  - Validates schema.
  - Returns setup plan object and next actions.

### Protected Sample Endpoint

- `GET /api/jpm/ping`
  - Requires internal bearer token/API key guard.
  - Calls a harmless JPM sandbox probe route (or mocked ping fallback).

---

## 4) Option A — Verify Artifacts Exist (Code Presence Checks)

Use these checks:

- File presence check (all paths in structure above).
- Startup import check (`node src/server.js`).
- Config validation check (`src/config/env.js` throws on missing required envs).
- Route registration check (`/health` returns 200).

Acceptance:

- All required modules present.
- App starts without syntax/config errors.
- `/health` operational.

---

## 5) Option B — Run Service Locally

### `package.json` scripts

```json
{
  "scripts": {
    "start": "node src/server.js",
    "dev": "node src/server.js",
    "test:curl": "echo \"Run scripts/test_api_matrix.ps1 (Windows) or .sh (Unix)\""
  }
}
```

### Local run sequence

1. `npm install express axios dotenv`
2. Create `.env` from `.env.example`
3. `npm run start`
4. Validate:
   - `curl http://localhost:8080/health`

Acceptance:

- Service binds configured port.
- No secret leakage in logs.
- Health endpoint returns 200 JSON.

---

## 6) Option C — Full Curl Test Matrix

## 6.1 OAuth Happy Path

```bash
curl --location "http://localhost:8080/api/oauth/token" \
  --header "Content-Type: application/json" \
  --data "{}"
```

Expected:

- 200
- JSON contains `access_token` or token metadata proxy result (sanitized logs only)

## 6.2 OAuth Invalid Credentials

- Set wrong `JPM_CLIENT_SECRET`.
Expected:
- 401/400 from upstream mapped clearly to client response.
- No secret value in logs or response.

## 6.3 Missing Scope

- Unset/empty `JPM_SCOPE`.
Expected:
- 400 validation error before upstream call.

## 6.4 Timeout/Retry

- Set unreachable `JPM_OAUTH_URL`.
Expected:
- 504/502 mapped error.
- Retry count logged with request ID.

## 6.5 Malformed Payload

```bash
curl -X POST http://localhost:8080/api/banking/setup \
  -H "Content-Type: application/json" \
  -d '{"entityName":123}'
```

Expected:

- 400 validation details.

## 6.6 Unauthorized Access

```bash
curl http://localhost:8080/api/jpm/ping
```

Expected:

- 401 (missing auth).

---

## 7) Option D — Side Effects, Logging, Secret Controls

### Logging Requirements

- Structured logs include:
  - requestId
  - route
  - statusCode
  - latency
  - upstream status
- Redact:
  - `client_secret`
  - `authorization`
  - any token-like string

### Secret Handling Controls

- Secrets never returned in API responses.
- Secrets never logged.
- Fail fast if required env vars absent.
- `.env` excluded from VCS via `.gitignore`.

### Error Handling

- Central error middleware:
  - Maps upstream errors to safe output.
  - Includes requestId for traceability.
  - Hides stack traces in production.

Acceptance:

- Logs are traceable and redacted.
- No plaintext secret/token leakage observed in test runs.
- Error responses are safe and actionable.

---

## 8) Minimal Implementation Skeleton Snippets

## `src/config/env.js`

```js
import 'dotenv/config';

const required = ['JPM_OAUTH_URL', 'JPM_CLIENT_ID', 'JPM_CLIENT_SECRET', 'JPM_SCOPE'];
for (const key of required) {
  if (!process.env[key]) throw new Error(`Missing required env var: ${key}`);
}

export const env = {
  port: Number(process.env.PORT || 8080),
  oauthUrl: process.env.JPM_OAUTH_URL,
  clientId: process.env.JPM_CLIENT_ID,
  clientSecret: process.env.JPM_CLIENT_SECRET,
  scope: process.env.JPM_SCOPE,
  grantType: process.env.JPM_GRANT_TYPE || 'client_credentials',
  timeoutMs: Number(process.env.REQUEST_TIMEOUT_MS || 15000)
};
```

## `src/services/jpmOAuthService.js`

```js
import axios from 'axios';
import { env } from '../config/env.js';

export async function fetchOAuthToken() {
  const body = new URLSearchParams({
    client_id: env.clientId,
    client_secret: env.clientSecret,
    grant_type: env.grantType,
    scope: env.scope
  });

  const res = await axios.post(env.oauthUrl, body.toString(), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    timeout: env.timeoutMs
  });

  return res.data;
}
```

## `src/routes/oauthRoutes.js`

```js
import { Router } from 'express';
import { fetchOAuthToken } from '../services/jpmOAuthService.js';

const router = Router();

router.post('/token', async (req, res, next) => {
  try {
    const data = await fetchOAuthToken();
    res.json({ ok: true, token_type: data.token_type, expires_in: data.expires_in, access_token: data.access_token });
  } catch (err) {
    next(err);
  }
});

export default router;
```

---

## 9) Final Thorough-Test Exit Criteria

All conditions must pass:

- [ ] Service starts and `/health` passes.
- [ ] OAuth happy path returns successful token response.
- [ ] Invalid creds path fails safely without secret leakage.
- [ ] Missing scope validation works.
- [ ] Timeout/retry path returns controlled error.
- [ ] Banking payload validation rejects malformed inputs.
- [ ] Unauthorized route returns 401.
- [ ] Logs show request IDs and redact secrets/tokens.
- [ ] No secrets committed to repository.

---

## 10) Notes for Equity Shield Advocates Production Readiness

- Replace sandbox endpoints/scopes with production values only after bank approval.
- Add secret manager integration (Vault/AWS/GCP/Azure) before go-live.
- Enable audit logging retention and access review process.
- Add CI pipeline checks for secret scanning and dependency vulnerabilities.

---

## 11) Operational Banking Documentation Linkage (Company Updates Integration)

For consolidated business-operations and governance execution alignment (LBWG, MERCDEE, Family Trust, AUM structure, phased rollout, and risk controls), reference:

- `COMPANY_UPDATES_AND_INTEGRATIONS_PLAN.md`
- `AUM_REVENUE_UPDATE.md`

This linkage keeps technical API implementation sequencing synchronized with legal/entity banking setup progress and trust separation controls.
