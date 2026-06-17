# Curl Test Matrix

## 1) Health

```bash
curl -i http://localhost:8080/health
```

## 2) OAuth Happy

```bash
curl --location "http://localhost:8080/api/oauth/token" \
  --header "Content-Type: application/json" \
  --data "{}"
```

## 3) OAuth Invalid Credentials

Set wrong `JPM_CLIENT_SECRET` in `.env`:

```bash
curl -i --location "http://localhost:8080/api/oauth/token" \
  --header "Content-Type: application/json" \
  --data "{}"
```

## 4) Missing Scope

Unset/empty `JPM_SCOPE` and restart service:

```bash
curl -i --location "http://localhost:8080/api/oauth/token" \
  --header "Content-Type: application/json" \
  --data "{}"
```

## 5) Timeout/Unreachable OAuth URL

Set unreachable `JPM_OAUTH_URL`:

```bash
curl -i --location "http://localhost:8080/api/oauth/token" \
  --header "Content-Type: application/json" \
  --data "{}"
```

## 6) Malformed Banking Payload

```bash
curl -i -X POST http://localhost:8080/api/banking/setup \
  -H "Content-Type: application/json" \
  -d '{"entityName":123}'
```

## 7) Banking Setup Valid (from file)

### macOS/Linux (bash/zsh)

```bash
curl -i -X POST "http://localhost:8080/api/banking/setup" \
  -H "Content-Type: application/json" \
  --data-binary @tests/banking_setup_valid.json
```

### Windows CMD (curl.exe)

```bat
curl.exe -i -X POST "http://localhost:8080/api/banking/setup" ^
  -H "Content-Type: application/json" ^
  --data-binary "@tests\banking_setup_valid.json"
```

### Windows PowerShell (recommended)

```powershell
curl.exe -i -X POST "http://localhost:8080/api/banking/setup" `
  -H "Content-Type: application/json" `
  --data-binary "@tests/family_trust_valid.json"
```

## 8) Family Trust Setup Valid (from file)

### macOS/Linux (bash/zsh) - Family Trust

```bash
curl -i -X POST "http://localhost:8080/api/banking/setup/family-trust" \
  -H "Content-Type: application/json" \
  --data-binary @tests/family_trust_valid.json
```

### Windows CMD (curl.exe) - Family Trust

```bat
curl.exe -i -X POST "http://localhost:8080/api/banking/setup/family-trust" ^
  -H "Content-Type: application/json" ^
  --data-binary "@tests\family_trust_valid.json"
```

### Windows PowerShell (recommended) - Family Trust

```powershell
curl.exe -i -X POST "http://localhost:8080/api/banking/setup/family-trust" `
  -H "Content-Type: application/json" `
  --data-binary "@tests/family_trust_valid.json"
```

## 9) EquityShield Setup Valid (from file)

### macOS/Linux (bash/zsh) - EquityShield

```bash
curl -i -X POST "http://localhost:8080/api/banking/setup/equityshield-advocates" \
  -H "Content-Type: application/json" \
  --data-binary @tests/equityshield_advocates_valid.json
```

### Windows CMD (curl.exe) - EquityShield

```bat
curl.exe -i -X POST "http://localhost:8080/api/banking/setup/equityshield-advocates" ^
  -H "Content-Type: application/json" ^
  --data-binary "@tests\equityshield_advocates_valid.json"
```

## 10) EquityShield Setup Invalid (from file)

```bash
curl -i -X POST "http://localhost:8080/api/banking/setup/equityshield-advocates" \
  -H "Content-Type: application/json" \
  --data-binary @tests/equityshield_advocates_invalid.json
```

## 11) Unauthorized Ping

```bash
curl -i http://localhost:8080/api/jpm/ping
```

## 12) Authorized Ping

```bash
curl -i http://localhost:8080/api/jpm/ping -H "x-api-key: <INTERNAL_API_KEY>"
```

## 13) Unauthorized Transactions List

```bash
curl -i "http://localhost:8080/api/banking/transactions"
```

## 14) Authorized Transactions List

```bash
curl -i "http://localhost:8080/api/banking/transactions" \
  -H "x-api-key: <INTERNAL_API_KEY>"
```

## 15) Authorized Transactions List With Filters

```bash
curl -i "http://localhost:8080/api/banking/transactions?accountId=acct_operating_001&type=credit&minAmount=1000&limit=5" \
  -H "x-api-key: <INTERNAL_API_KEY>"
```

## 16) Transactions Invalid Amount Range

```bash
curl -i "http://localhost:8080/api/banking/transactions?minAmount=5000&maxAmount=100" \
  -H "x-api-key: <INTERNAL_API_KEY>"
```

## Windows syntax notes (important)

- Use `curl.exe` explicitly in PowerShell to avoid alias behavior.
- Keep the `@` attached to the path in one token:
  - Correct: `--data-binary "@tests\family_trust_valid.json"`
  - Incorrect: `--data-binary @ tests\family_trust_valid.json`
- Run commands from the repository root so relative `tests/...` paths resolve correctly.
