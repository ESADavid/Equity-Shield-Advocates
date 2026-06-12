# System Topology

## Overview

This repository implements a Node.js/Express integration layer that fronts JPM-related workflows and AI helper endpoints. The topology is organized around:

- Route layer (`src/routes/*`) for HTTP surface area
- Middleware layer (`src/middleware/*`) for request IDs, auth, and error handling
- Service layer (`src/services/*`) for JPM upstream interactions and domain logic
- Utility/config layer (`src/utils/*`, `src/config/*`) for logging, redaction, and environment management

## Runtime Topology (Logical)

```mermaid
flowchart TD
  C[Client / Curl / Script] --> S[Express Server src/server.js]

  S --> MW1[requestId middleware]
  MW1 --> MW2[JSON/body parsing]
  MW2 --> R[Route Handlers]

  R --> H[healthRoutes]
  R --> O[oauthRoutes]
  R --> B[bankingRoutes]
  R --> A[aiRoutes]
  R --> P[/api/jpm/ping + authGuard]

  P --> AG[authGuard middleware]

  O --> SO[jpmOAuthService]
  B --> SB[bankingSetupService]
  SB --> JC[jpmApiClient]
  SO --> JC

  A --> PY[Python-backed AI modules/invocations]

  JC --> JPM[JPM Upstream APIs]

  S --> EH[errorHandler middleware]
  R --> EH

  S --> LG[logger + redaction utils]
```

## Request Path Topology

### 1) Health

- `GET /health`
- Path:
  1. Client request
  2. Request ID middleware assigns `requestId`
  3. `healthRoutes` returns service metadata
- No auth required

### 2) OAuth Token Flow

- `POST /api/oauth/token`
- Path:
  1. Route validation/dispatch
  2. `jpmOAuthService` constructs upstream OAuth call
  3. `jpmApiClient` sends request to JPM
  4. Safe error mapping via centralized error handler
- Typical outcomes:
  - 200 on success
  - 400/5xx mapped for upstream failures

### 3) Banking Setup

- `POST /api/banking/setup`
- Path:
  1. JSON payload parsed by Express
  2. `bankingRoutes` delegates to `bankingSetupService`
  3. `bankingSetupService` may use `jpmApiClient`
- Malformed JSON never reaches service logic; it fails at parser with 400

### 4) Protected Ping

- `GET /api/jpm/ping`
- Path:
  1. `authGuard` checks either:
     - `Authorization: Bearer <INTERNAL_API_KEY>`, or
     - `x-api-key: <INTERNAL_API_KEY>`
  2. If valid, route executes; otherwise returns 401

### 5) AI Endpoints

- `/api/ai/*` routes fan into AI analysis/predict/report flows
- HTTP API remains in Express while analysis logic is in Python modules/tests present in repo

## Security Topology

- Environment-backed secrets centralized in `src/config/env.js`
- Auth boundary enforced in `src/middleware/authGuard.js`
- Logging pipeline uses redaction utilities to avoid leaking secrets
- Correlation via `requestId` supports safer operational tracing

## Testing Topology

- Cross-platform curl matrices:
  - Windows: `scripts/test_api_matrix.ps1`
  - Unix: `scripts/test_api_matrix.sh`
- Matrix behavior depends on:
  - Correct JSON payload serialization in shell
  - Presence/absence of `INTERNAL_API_KEY` for auth scenarios

## Notes for Windows Shell Reliability

PowerShell inline escaping for `curl.exe -d "{...}"` is fragile. Prefer:

- PowerShell hashtables + `ConvertTo-Json`
- Then pass generated JSON as body to avoid malformed payload parsing errors
