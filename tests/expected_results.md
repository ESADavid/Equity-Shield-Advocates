# Expected Results

## Option A - Artifact/Startup Checks

- All required files exist.
- `node src/server.js` starts without syntax errors.
- `GET /health` returns 200.

## Option B - Local Run

- Service listens on configured `PORT` (default 8080).
- Logs are structured JSON and include requestId.
- No plaintext secrets in logs.

## Option C - Curl Matrix

1. OAuth happy path:
   - 200 with token metadata.
2. Invalid credentials:
   - 400/401 mapped error with safe message.
3. Missing scope:
   - 400 validation error before upstream success.
4. Timeout/unreachable OAuth:
   - 504 timeout or 502 unreachable mapped safely.
5. Malformed banking payload:
   - 400 with validation details.
6. Unauthorized ping:
   - 401.
7. Authorized ping:

   - 1.

## Option D - Side Effects / Secret Controls

- Responses include requestId for tracing.
- Logs include route/status/latency.
- Redaction masks:
  - client_secret
  - authorization
  - token-like values
- `.env` excluded via `.gitignore`.
