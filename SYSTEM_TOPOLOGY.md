# Equity Shield Advocates — End-to-End System Topology

## 1) Topology Scope

This document describes the **end-to-end topology** of the Node/Express platform, including:

- Entry points and mounted routes
- Middleware sequence and control points
- Internal service interactions
- External dependency interactions (JPM OAuth/API)
- Security boundaries (auth, secrets, redaction)
- Observability and error propagation paths

Primary code anchors reviewed:

- `src/server.js`
- `src/routes/oauthRoutes.js`
- `src/routes/bankingRoutes.js`
- `jpm_integration_artifacts.md` (target architecture/intended behaviors)

---

## 2) High-Level Architecture (E2E)

```mermaid
flowchart LR
    C[Client / Internal Consumer] --> S[Express Server: src/server.js]

    S --> M1[express.json]
    M1 --> M2[requestIdMiddleware]
    M2 --> M3[request_complete logger hook]

    M3 --> H[/health routes/]
    M3 --> O[/api/oauth routes/]
    M3 --> B[/api/banking routes/]
    M3 --> J[/api/jpm routes/]
    M3 --> A[/api/ai routes (conditional)/]

    O --> O1[fetchOAuthToken]
    O1 --> X1[JPM OAuth Endpoint]

    B --> B1[buildBankingSetupPlan]
    B --> B2[buildFamilyTrustIntegrationPlan]
    B --> B3[buildEquityShieldAdvocatesIntegrationPlan]
    B --> B4[authGuard -> pingJpmSandbox]
    B --> B5[authGuard -> listTransactions]

    B4 --> X2[JPM Sandbox/API endpoint]

    S --> NF[notFoundHandler]
    S --> EH[errorHandler]

    EH --> C
    H --> C
    O --> C
    B --> C
    J --> C
```

---

## 3) Runtime Request Pipeline

For all incoming requests:

1. **JSON parsing** via `express.json({ limit: '1mb' })`
2. **Request ID assignment** via `requestIdMiddleware`
3. **Completion logging hook** (`res.on('finish')`) emits:
   - `requestId`
   - `route`
   - `method`
   - `statusCode`
   - `latency`
4. Route dispatch based on mount path
5. On misses: `notFoundHandler`
6. On thrown/forwarded errors: centralized `errorHandler`

### Mounted route topology (`src/server.js`)

- `/health` → `healthRoutes`
- `/api/oauth` → `oauthRoutes`
- `/api/banking` → `bankingRoutes`
- `/api/jpm` → `bankingRoutes` (aliasing JPM-oriented endpoints in same router)
- `/api/ai` → conditionally loaded (`DISABLE_AI_ROUTES` gate)

---

## 4) Endpoint-to-Service End-to-End Map

## A) Health

- **Path:** `GET /health`
- **Flow:** Client → middleware chain → `healthRoutes` → response
- **External calls:** none
- **Primary use:** liveness/readiness and deployment checks

## B) OAuth Token Retrieval

- **Path:** `POST /api/oauth/token`
- **Route file:** `src/routes/oauthRoutes.js`
- **Service:** `fetchOAuthToken(req.requestId)` in `src/services/jpmOAuthService.js`
- **External dependency:** JPM OAuth endpoint
- **Response shape (current route):**
  - `ok`, `token_type`, `expires_in`, `access_token`, `requestId`

**Trust boundary crossing:** internal service → external JPM OAuth platform

## C) Banking Setup Planning

- **Base router:** `src/routes/bankingRoutes.js`
- **Endpoints:**
  - `POST /api/banking/setup`
  - `POST /api/banking/setup/business`
  - `POST /api/banking/setup/family-trust`
  - `POST /api/banking/setup/equityshield-advocates`
- **Services:**
  - `buildBankingSetupPlan`
  - `buildFamilyTrustIntegrationPlan`
  - `buildEquityShieldAdvocatesIntegrationPlan`
- **External calls:** none (planning/validation oriented)
- **Validation behavior:** route-local validation handler returns 400 with structured details

## D) JPM Ping / Transactions (Protected)

- **Endpoints:**
  - `GET /api/banking/ping` (also reachable under `/api/jpm/ping` due to alias mount)
  - `GET /api/banking/transactions` (also under `/api/jpm/transactions`)
- **Protection:** `authGuard` middleware required
- **Services:**
  - `pingJpmSandbox(req.requestId)` (external probe call)
  - `listTransactions(req.query)` (internal retrieval/processing)

---

## 5) Security & Trust Boundaries

## Boundary 1 — Client to API Edge

- Input enters through Express routes
- JSON parser limits payload size to 1 MB
- Request identity correlation is established early (`requestIdMiddleware`)

## Boundary 2 — Protected Internal Operations

- `authGuard` gates privileged JPM-related endpoints
- Unauthorized requests should fail before service execution

## Boundary 3 — External JPM Integrations

- OAuth token retrieval and sandbox ping cross network boundary to JPM systems
- Upstream errors are expected to be normalized by centralized error handling

## Secrets/Token Handling (as intended by artifacts)

Per `jpm_integration_artifacts.md`, required controls include:

- No secret/token leakage in logs
- Redaction of sensitive fields (e.g., `client_secret`, `authorization`, token-like values)
- Fail-fast env validation for required JPM config

---

## 6) Observability Topology

Current core observability path from `src/server.js`:

- Structured completion log on every response completion
- Emits request metadata + latency and status code
- Correlated by `requestId`

Recommended correlation chain (E2E):

- API edge request log (`request_complete`)
- Route/service logs include same `requestId`
- Upstream JPM call logs capture upstream status/latency while redacting secrets

---

## 7) Error Propagation Topology

1. Route/service throws or `next(err)`
2. Optional route-level special handlers run first (e.g., malformed JSON in `bankingRoutes`)
3. Centralized `errorHandler` finalizes safe response envelope
4. Client receives sanitized error with request correlation ID when available

This enforces a single termination point for unhandled errors and consistent client behavior.

---

## 8) AI Route Conditional Topology

- `DISABLE_AI_ROUTES` env flag determines whether `./routes/aiRoutes.js` is mounted
- If disabled: explicit info log
- If enabled but dynamic import fails: error log emitted; server still continues with core banking/oauth routes

This isolates AI route availability from critical banking route boot success.

---

## 9) End-to-End Sequence Examples

## Example 1: OAuth token success

1. Client calls `POST /api/oauth/token`
2. Request ID assigned
3. Route calls `fetchOAuthToken(requestId)`
4. Service calls JPM OAuth endpoint
5. Response mapped to API payload and returned
6. `request_complete` log emitted

## Example 2: Unauthorized JPM ping

1. Client calls `GET /api/jpm/ping` without auth
2. `authGuard` rejects
3. Error handling path returns 401
4. `request_complete` still logs with status and latency

## Example 3: Malformed JSON setup payload

1. Client posts invalid JSON to `/api/banking/setup`
2. JSON parser raises parse error
3. Banking router parse-failed handler returns 400 `Malformed JSON body`
4. Completion log emitted with 400

---

## 10) Topology Risks / Notes

- `oauthRoutes` currently returns `access_token` to caller by design; this may be acceptable for internal trusted consumers but should be reviewed against least-exposure policy.
- `/api/jpm` and `/api/banking` both mount `bankingRoutes`; endpoint duplication should be intentional/documented to avoid confusion.
- Full topology verification of all components (e.g., logger redaction internals, env validation strictness, AI route internals) requires direct inspection of remaining modules not covered in this specific pass.

---

## 11) Concise Endpoint Inventory (Current)

- `GET /health`
- `POST /api/oauth/token`
- `POST /api/banking/setup`
- `POST /api/banking/setup/business`
- `POST /api/banking/setup/family-trust`
- `POST /api/banking/setup/equityshield-advocates`
- `GET /api/banking/ping` (auth required)
- `GET /api/banking/transactions` (auth required)
- Alias exposure via `/api/jpm/*` for banking router endpoints
- Conditional: `/api/ai/*` when enabled

---

## 12) E2E Topology Summary

The system is structured as a layered API gateway pattern:

- **Edge layer:** Express + middleware for parsing, request identity, and completion metrics
- **Routing layer:** Feature-separated routers (`health`, `oauth`, `banking`)
- **Service layer:** JPM OAuth client, JPM API client, banking setup planners, transactions logic
- **Control layer:** auth guard + centralized error handling
- **External layer:** JPM OAuth and sandbox/API endpoints

This supports traceable end-to-end request execution with clear insertion points for security controls, redaction, and resilience policies.
